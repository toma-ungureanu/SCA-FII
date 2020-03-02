package communication;

import crypto.AsymKeysInfrastructure;
import crypto.SymKeysInfrastructure;
import org.jetbrains.annotations.NotNull;
import utils.Utils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.net.*;
import java.io.*;
import java.security.*;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import static utils.Utils.*;

public class Client
{
    private static final int CLIENT_TO_MERCHANT_PORT = 50000;
    private static final String ACKNOWLEDGE = "Ready for communication!" + CLIENT_TO_MERCHANT_PORT;
    private static final String PRIVATE_KEY_PATH = "\\customer_keys\\privateKey.key";
    private static final String PUBLIC_KEY_PATH = "\\customer_keys\\publicKey.pub";
    private static final String DATE_FORMAT = "MM/yyyy";
    private static final String CARD_REGEX = "^(?:4[0-9]{12}(?:[0-9]{3})?|[25][1-7][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]" +
            "{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\\d{3})\\d{11})$";
    private static final String PIN_REGEX = "^[0-9]{4}$";
    private static final int SIZE_OF_LONG = 8;
    private static final int SIZE_OF_DOUBLE = 8;

    private AsymKeysInfrastructure asymKeysInfr;
    private SymKeysInfrastructure symKeysInfr;
    private PublicKey merchantPubKey;
    private Socket client2MerchantSocket;
    private ObjectInputStream client2MerchantInput;
    private ObjectOutputStream client2MerchantOutput;
    private long sessionID;

    public Client(String address)
    {
        if (!initMerchantConnection(address))
        {
            throw new ExceptionInInitializerError("Error while initializing connection!");
        }

        this.asymKeysInfr = new AsymKeysInfrastructure();
        if (!this.asymKeysInfr.loadRSAKeys(PUBLIC_KEY_PATH, PRIVATE_KEY_PATH))
        {
            this.asymKeysInfr.initRSAKeyPairs();
            this.asymKeysInfr.saveKeys(PUBLIC_KEY_PATH, PRIVATE_KEY_PATH);
        }

        try
        {
            this.symKeysInfr = new SymKeysInfrastructure(null);
        }
        catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException |
                InvalidAlgorithmParameterException exception)
        {
            exception.printStackTrace();
        }
    }

    public boolean client2MerchantHandshake() throws IOException, ClassNotFoundException
    {
        // merchant -> client : merchantPubKey
        this.client2MerchantInput = new ObjectInputStream(this.client2MerchantSocket.getInputStream());
        this.merchantPubKey = (PublicKey) client2MerchantInput.readObject();

        // client -> merchant : clientPubKey
        this.client2MerchantOutput = new ObjectOutputStream(this.client2MerchantSocket.getOutputStream());
        client2MerchantOutput.writeObject(this.asymKeysInfr.getPublicKey());

        // client -> merchant: {clientSymmetricKey}merchantPubKey
        byte[] encrCustomerSymKey = asymKeysInfr.encryptDecryptMessage(symKeysInfr.getSecretKey().getEncoded(), Cipher.ENCRYPT_MODE, merchantPubKey, null);
        client2MerchantOutput.writeObject(encrCustomerSymKey);

        // merchant -> client: {acknowledgement}clientSymmetricKey
        byte[] encrAcknowledge = (byte[]) client2MerchantInput.readObject();
        byte[] acknowledge = symKeysInfr.decryptMessage(encrAcknowledge);
        if (Arrays.equals(acknowledge, ACKNOWLEDGE.getBytes()))
        {
            System.out.println("Communication is secure, you can proceed!");
            return true;
        }
        else
        {
            return false;
        }
    }

    public boolean receiveSession() throws ClassNotFoundException, IOException, NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException
    {
        byte[] encrMsg = (byte[]) client2MerchantInput.readObject();
        byte[] decrMsg = symKeysInfr.decryptMessage(encrMsg);
        int sessionIDsize = decrMsg[0];

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(decrMsg, 1, sessionIDsize);
        byte[] sessionIDBytes = out.toByteArray();

        out.reset();
        out.write(decrMsg, sessionIDsize + 1, decrMsg.length - sessionIDsize - 1);
        byte[] encrSignature = out.toByteArray();

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, merchantPubKey);
        byte[] decryptedMessageHash = cipher.doFinal(encrSignature);
        byte[] toCompare = MessageDigest.getInstance("SHA-256").digest(sessionIDBytes);
        if (decryptedMessageHash.length != toCompare.length)
        {
            return false;
        }

        for (int i = 0; i < decryptedMessageHash.length; i++)
        {
            if (decryptedMessageHash[i] != toCompare[i])
            {
                return false;
            }
        }

        this.sessionID = bytesToLong(sessionIDBytes);
        System.out.println("Session id is: " + this.sessionID);
        return true;
    }

    public boolean sendCommandInfo(String cardNumber, String expDate, String pin, double amount, String merchantName,
                                   String orderDesc) throws IOException
    {
        byte[] pm = preparePM(cardNumber, expDate, pin, amount, merchantName);
        byte[] po = preparePO(orderDesc, amount);
        if( pm == null || po == null)
        {
            return false;
        }

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(pm.length);
        outputStream.write(pm);
        outputStream.write(po);
        client2MerchantOutput.writeObject(outputStream.toByteArray());
        return true;
    }

    private byte[] preparePM(String cardNumber, String expDate, String pin, double amount, String merchantName)
    {
        if (!checkCard(cardNumber, expDate, pin))
        {
            return null;
        }

        try
        {
            byte[] piToSign = createPiToSign(cardNumber, expDate, pin, amount, merchantName);
            byte[] signedPi = generateSignature(piToSign, this.asymKeysInfr.getPrivateKey());
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(piToSign.length);
            outputStream.write(piToSign);
            outputStream.write(signedPi);
            byte[] pm = outputStream.toByteArray();
            byte[] encrPm = symKeysInfr.encryptMessage(pm);
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | IOException exception)
        {
            exception.printStackTrace();
        }
        return null;
    }

    private byte[] preparePO(String orderDesc, double amount)
    {
        try
        {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            String toSign = orderDesc + sessionID + amount + generateNonce();
            byte[] signature = generateSignature(toSign.getBytes(), this.asymKeysInfr.getPrivateKey());
            outputStream.write(toSign.getBytes().length);
            outputStream.write(toSign.getBytes());
            outputStream.write(signature);
            return outputStream.toByteArray();
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | IOException exception)
        {
            exception.printStackTrace();
            return null;
        }
    }


    private byte[] createPiToSign(String cardNumber, String expDate, String pin, double amount, String merchantName) throws IOException
    {
        /* Payload looks like this:

        CardN_Length + CardN + ExpDate_Length + ExpDate +
        PIN_length + PIN + SessionID_Length + SessionID +
        Amount_Size + Amount + NOnce_Size + NOnce +
        MerchantName_Length + MerchantName

        */

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(cardNumber.length());
        outputStream.write(cardNumber.getBytes());

        outputStream.write(expDate.length());
        outputStream.write(expDate.getBytes());

        outputStream.write(pin.length());
        outputStream.write(pin.getBytes());

        outputStream.write(SIZE_OF_LONG);
        outputStream.write(longToBytes(this.sessionID));

        outputStream.write(SIZE_OF_DOUBLE);
        outputStream.write(doubleToBytes(amount));

        outputStream.write(SIZE_OF_LONG);
        outputStream.write(longToBytes(generateNonce()));

        outputStream.write(merchantName.length());
        outputStream.write(merchantName.getBytes());

        outputStream.write(this.asymKeysInfr.getPublicKey().getEncoded().length);
        outputStream.write(this.asymKeysInfr.getPublicKey().getEncoded());

        return outputStream.toByteArray();
    }



    private boolean checkCard(String cardNumber, String expDate, String pin)
    {
        LocalDate expirationDate = LocalDate.parse(expDate, DateTimeFormatter.ofPattern(DATE_FORMAT));
        LocalDate today = LocalDate.now(ZoneId.systemDefault());
        Pattern pattern = Pattern.compile(CARD_REGEX);
        Matcher matcher = pattern.matcher(cardNumber);
        if (!matcher.find())
        {
            System.out.println("Incorrect card number!");
            return false;
        }

        if (!checkLuhn(cardNumber))
        {
            System.out.println("Incorrect card number!");
            return false;
        }

        if (today.isBefore(expirationDate))
        {
            System.out.println("Card is expired!");
            return false;
        }

        pattern = Pattern.compile(PIN_REGEX);
        matcher = pattern.matcher(pin);
        if (!matcher.find())
        {
            System.out.println("Incorrect PIN!");
            return false;
        }
        return true;
    }

    private boolean initMerchantConnection(String address)
    {
        try
        {
            this.client2MerchantSocket = new Socket(address, CLIENT_TO_MERCHANT_PORT);
            System.out.println("Connected to the merchant!");
            return true;
        }
        catch (IOException exception)
        {
            exception.printStackTrace();
            return false;
        }
    }

    public static void main(String[] args) throws IOException, ClassNotFoundException, IllegalBlockSizeException,
            InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException
    {
        String address = "127.0.0.1";
        Client client = new Client(address);
        if (!client.client2MerchantHandshake())
        {
            System.out.println("Cannot proceed, communication handshake failed!");
        }
        if (!client.receiveSession())
        {
            System.out.println("Session initialization failed! Aborting...");
        }


        String expDate = "01-2022";
        String cardNumber = "4197394215553472";
        String PIN = "1234";
        String merchantName = "EMag";
        double amount = 4195.95;
        String orderDesc = "Produse: 1 x Laptop Lenovo, 16Gb RAM 2400MHZ, i7 6-core 3.7GHZ, GTX-1060Ti, SSD-512GB";


        if (!client.sendCommandInfo(cardNumber, expDate, PIN, amount, merchantName, orderDesc))
        {
            System.out.println("Order could not be sent!");
        }
    }
}