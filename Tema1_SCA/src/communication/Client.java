package communication;

import crypto.AsymKeysInfrastructure;
import crypto.SymKeysInfrastructure;

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
    private static final int CLIENT_TO_MERCHANT_PORT = 40000;
    private static final int CLIENT_TO_PG_PORT = 60000;
    private static final String ACKNOWLEDGE_MERCHANT = "Ready for communication!" + CLIENT_TO_MERCHANT_PORT;
    private static final String ACKNOWLEDGE_PAYMENT_GATEWAY = "Ready for communication!" + CLIENT_TO_PG_PORT;
    private static final String PRIVATE_KEY_PATH = "\\customer_keys\\privateKey.key";
    private static final String PUBLIC_KEY_PATH = "\\customer_keys\\publicKey.pub";
    private static final String DATE_FORMAT = "dd/MM/yyyy";
    private static final String CARD_REGEX = "^(?:4[0-9]{12}(?:[0-9]{3})?|[25][1-7][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]" +
            "{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\\d{3})\\d{11})$";
    private static final String PIN_REGEX = "^[0-9]{4}$";

    private AsymKeysInfrastructure asymKeysInfr;
    private SymKeysInfrastructure client2MerchantSymKeysInfr;
    private SymKeysInfrastructure client2PgSymKeysInfr;

    private PublicKey merchantPubKey;
    private PublicKey pgPubKey;

    private Socket client2MerchantSocket;
    private Socket client2PgSocket;

    private ObjectInputStream client2MerchantInput;
    private ObjectInputStream client2PgInput;

    private ObjectOutputStream client2MerchantOutput;
    private ObjectOutputStream client2PgOutput;

    private long sessionID;

    public Client(String address)
    {
        this.asymKeysInfr = new AsymKeysInfrastructure();
        if (!this.asymKeysInfr.loadRSAKeys(PUBLIC_KEY_PATH, PRIVATE_KEY_PATH))
        {
            this.asymKeysInfr.initRSAKeyPairs();
            this.asymKeysInfr.saveKeys(PUBLIC_KEY_PATH, PRIVATE_KEY_PATH);
        }

        try
        {
            this.client2MerchantSymKeysInfr = new SymKeysInfrastructure(null);
            this.client2PgSymKeysInfr  = new SymKeysInfrastructure(null);
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
        byte[] encrCustomerSymKey = asymKeysInfr.encryptDecryptMessage(client2MerchantSymKeysInfr.getSecretKey().getEncoded(), Cipher.ENCRYPT_MODE, merchantPubKey, null);
        client2MerchantOutput.writeObject(encrCustomerSymKey);

        // merchant -> client: {acknowledgement}clientSymmetricKey
        byte[] encrAcknowledge = (byte[]) client2MerchantInput.readObject();
        byte[] acknowledge = client2MerchantSymKeysInfr.decryptMessage(encrAcknowledge);
        if (Arrays.equals(acknowledge, ACKNOWLEDGE_MERCHANT.getBytes()))
        {
            System.out.println("Communication is secure, you can proceed!");
            return true;
        }
        else
        {
            return false;
        }
    }

    public boolean client2pgHandshake() throws IOException, ClassNotFoundException
    {
        // payment gateway -> client : payment gateway PubKey
        this.client2PgInput = new ObjectInputStream(this.client2PgSocket.getInputStream());
        this.pgPubKey = (PublicKey) client2PgInput.readObject();

        // client -> payment gateway : clientPubKey
        this.client2PgOutput = new ObjectOutputStream(this.client2PgSocket.getOutputStream());
        client2PgOutput.writeObject(this.asymKeysInfr.getPublicKey());

        // client -> payment gateway: {clientSymmetricKey}pgPubKey
        byte[] encrCustomerSymKey = asymKeysInfr.encryptDecryptMessage(client2PgSymKeysInfr.getSecretKey().getEncoded(), Cipher.ENCRYPT_MODE, pgPubKey, null);
        client2PgOutput.writeObject(encrCustomerSymKey);

        // merchant -> client: {acknowledgement}clientSymmetricKey
        byte[] encrAcknowledge = (byte[]) client2PgInput.readObject();
        byte[] acknowledge = client2PgSymKeysInfr.decryptMessage(encrAcknowledge);
        if (Arrays.equals(acknowledge, ACKNOWLEDGE_PAYMENT_GATEWAY.getBytes()))
        {
            System.out.println("Communication between client and payment gateway is secure, you can proceed!");
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
        byte[] decrMsg = client2MerchantSymKeysInfr.decryptMessage(encrMsg);
        int sessionIDsize = decrMsg[0];

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(decrMsg, 1, sessionIDsize);
        byte[] sessionIDBytes = out.toByteArray();

        out.reset();
        out.write(decrMsg, sessionIDsize + 1, decrMsg.length - sessionIDsize - 1);
        byte[] encrSignature = out.toByteArray();

        if (!checkSignature(encrSignature, merchantPubKey, sessionIDBytes))
        {
            return false;
        }

        this.sessionID = bytesToLong(sessionIDBytes);
        System.out.println("Session id is: " + this.sessionID);
        return true;
    }

    public boolean sendCommandInfo(String cardNumber, String expDate, String pin, double amount, String merchantName,
                                   String orderDesc) throws IOException
    {
        byte[] pm = preparePM(cardNumber, expDate, pin, amount, merchantName);
        if (pm == null)
        {
            System.out.println("Couldn't establish the payment information");
            return false;
        }

        byte[] po = preparePO(orderDesc, amount);
        if (po == null)
        {
            return false;
        }

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(intToBytes(pm.length));
        outputStream.write(pm);
        outputStream.write(po);
        client2MerchantOutput.writeObject(this.client2MerchantSymKeysInfr.encryptMessage(outputStream.toByteArray()));
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
            return client2PgSymKeysInfr.encryptMessage(pm);

        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | IOException exception)
        {
            exception.printStackTrace();
            return null;
        }
    }

    private byte[] preparePO(String orderDesc, double amount)
    {
        try
        {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            byte[] toSign = preparePOPayload(orderDesc, amount);
            byte[] signature = generateSignature(toSign, this.asymKeysInfr.getPrivateKey());
            outputStream.write(toSign.length);
            outputStream.write(toSign);
            outputStream.write(signature);
            return outputStream.toByteArray();
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | IOException exception)
        {
            exception.printStackTrace();
            return null;
        }
    }

    private byte[] preparePOPayload(String orderDesc, double amount) throws IOException
    {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        long nonce = generateNonce();
        System.out.println("NONCE IS: " +  nonce);
        int poSize = intToBytes(orderDesc.length()).length +
                     orderDesc.getBytes().length +
                     intToBytes(Long.BYTES).length +
                     longToBytes(sessionID).length +
                     intToBytes(Double.BYTES).length +
                     doubleToBytes(amount).length +
                     intToBytes(Long.BYTES).length +
                     longToBytes(nonce).length;

        outputStream.write(intToBytes(poSize));

        outputStream.write(intToBytes(orderDesc.length()));
        outputStream.write(orderDesc.getBytes());

        outputStream.write(intToBytes(Long.BYTES));
        outputStream.write(longToBytes(sessionID));

        outputStream.write(intToBytes(Double.BYTES));
        outputStream.write(doubleToBytes(amount));

        outputStream.write(intToBytes(Long.BYTES));
        outputStream.write(longToBytes(nonce));

        return outputStream.toByteArray();
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

        outputStream.write(intToBytes(cardNumber.length()));
        outputStream.write(cardNumber.getBytes());

        outputStream.write(intToBytes(expDate.length()));
        outputStream.write(expDate.getBytes());

        outputStream.write(intToBytes(pin.length()));
        outputStream.write(pin.getBytes());

        outputStream.write(intToBytes(Long.BYTES));
        outputStream.write(longToBytes(this.sessionID));

        outputStream.write(intToBytes(Double.BYTES));
        outputStream.write(doubleToBytes(amount));

        outputStream.write(intToBytes(this.asymKeysInfr.getPublicKey().getEncoded().length));
        outputStream.write(this.asymKeysInfr.getPublicKey().getEncoded());

        outputStream.write(intToBytes(Integer.BYTES));
        outputStream.write(longToBytes(generateNonce()));

        outputStream.write(intToBytes(merchantName.length()));
        outputStream.write(merchantName.getBytes());

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

        if (expirationDate.isBefore(today))
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

    public boolean initMerchantConnection(String address)
    {
        try
        {
            this.client2MerchantSocket = new Socket(address, CLIENT_TO_MERCHANT_PORT);
            return true;
        }
        catch (IOException exception)
        {
            exception.printStackTrace();
            return false;
        }
    }

    public boolean initPgConnection(String address)
    {
        try
        {
            this.client2PgSocket = new Socket(address, CLIENT_TO_PG_PORT);
            return true;
        }
        catch (IOException exception)
        {
            exception.printStackTrace();
            return false;
        }
    }

    public void connect(String address) throws IOException, ClassNotFoundException, IllegalBlockSizeException,
            InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException
    {
        if (!initMerchantConnection(address))
        {
            throw new ExceptionInInitializerError("Error while initializing connection with the merchant!");
        }

        if (!client2MerchantHandshake())
        {
            throw new ExceptionInInitializerError("Cannot proceed, communication handshake with merchant failed!");
        }
        System.out.println("Connection with merchant succeeded!\n");

        if (!receiveSession())
        {
            throw new ExceptionInInitializerError("Session initialization failed! Aborting...");
        }

        if (!initPgConnection(address))
        {
            throw new ExceptionInInitializerError("Error while initializing connection with the payment gateway!");
        }

        if (!client2pgHandshake())
        {
            throw new ExceptionInInitializerError("Error while initializing connection with the payment gateway!");
        }
        System.out.println("Connection with payment gateway succeeded!");
    }

    public void command(String cardNumber, String expDate, String PIN, double amount, String merchantName, String orderDesc) throws IOException
    {
        if (!sendCommandInfo(cardNumber, expDate, PIN, amount, merchantName, orderDesc))
        {
            System.out.println("Order could not be sent!");
        }
        System.out.println("Order sent!");
    }

    public static void main(String[] args) throws IOException, ClassNotFoundException, IllegalBlockSizeException,
            InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException
    {
        String address = "127.0.0.1";
        Client client = new Client(address);
        client.connect(address);

        String expDate = "01/01/2022";
        String cardNumber = "4197394215553472";
        String PIN = "1234";
        String merchantName = "EMag";
        double amount = 4195.95;
        String orderDesc = "Produse: 1 x Laptop Lenovo, 16Gb RAM 2400MHZ, i7 6-core 3.7GHZ, GTX-1060Ti, SSD-512GB";

        client.command(cardNumber, expDate, PIN, amount, merchantName, orderDesc);
    }
}