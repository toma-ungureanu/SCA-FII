package communication;

import crypto.AsymKeysInfrastructure;
import crypto.SymKeysInfrastructure;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;

import static utils.Utils.*;

public class Client
{
private static final int CLIENT_TO_MERCHANT_PORT = 40000;
private static final int CLIENT_TO_PG_PORT = 60000;
private static final String ACKNOWLEDGE_MERCHANT = "Ready for communication!" + CLIENT_TO_MERCHANT_PORT;
private static final String ACKNOWLEDGE_PAYMENT_GATEWAY = "Ready for communication!" + CLIENT_TO_PG_PORT;
private static final String PRIVATE_KEY_PATH = "\\customer_keys\\privateKey.key";
private static final String PUBLIC_KEY_PATH = "\\customer_keys\\publicKey.pub";

private double amount;
private AsymKeysInfrastructure asymKeysInfr;
private ObjectInputStream client2MerchantInput;
private ObjectOutputStream client2MerchantOutput;
private SymKeysInfrastructure client2MerchantSymKeysInfr;
private Socket client2MerchantSocket;
private Socket client2PgSocket;
private SymKeysInfrastructure client2PgSymKeysInfr;
private PublicKey merchantPubKey;
private long sessionID;

public Client()
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

public void command(String cardNumber, String expDate, String PIN, double amount, String merchantName, String orderDesc)
{
    try
    {
        this.amount = amount;
        if (!sendCommandInfo(cardNumber, expDate, PIN, amount, merchantName, orderDesc))
        {
            System.out.println("Order could not be sent!");
            return;
        }
        System.out.println("Order sent! Waiting for response...");

        if (!receiveResponseFromMerchant())
        {
            System.out.println("Something went wrong while processing the response. Aborting...");
            return;
        }
        System.out.println("Command processed successfully!");
    }
    catch (ClassNotFoundException | NoSuchAlgorithmException | BadPaddingException | InvalidKeyException |
            NoSuchPaddingException | IOException | IllegalBlockSizeException e)
    {
        e.printStackTrace();
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

    if (!client2PgHandshake())
    {
        throw new ExceptionInInitializerError("Error while initializing connection with the payment gateway!");
    }
    System.out.println("Connection with payment gateway succeeded!");
}

private boolean client2MerchantHandshake() throws IOException, ClassNotFoundException
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

private boolean client2PgHandshake() throws IOException, ClassNotFoundException
{
    // payment gateway -> client : payment gateway PubKey
    ObjectInputStream client2PgInput = new ObjectInputStream(this.client2PgSocket.getInputStream());
    PublicKey pgPubKey = (PublicKey) client2PgInput.readObject();

    // client -> payment gateway : clientPubKey
    ObjectOutputStream client2PgOutput = new ObjectOutputStream(this.client2PgSocket.getOutputStream());
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

    outputStream.write(intToBytes(Long.BYTES));
    outputStream.write(longToBytes(generateNonce()));

    outputStream.write(intToBytes(merchantName.length()));
    outputStream.write(merchantName.getBytes());

    return outputStream.toByteArray();
}

private boolean deserializePayloadFromMerchant(byte[] decrResponse) throws IOException, IllegalBlockSizeException,
        InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException
{
    int offset = 0;
    byte[] responseBytes = deserializeItem(decrResponse, offset);
    offset += responseBytes.length;
    offset += Integer.BYTES;
    byte[] sessionIDBytes = deserializeItem(decrResponse, offset);
    offset += sessionIDBytes.length;
    offset += Integer.BYTES;
    if (this.sessionID != bytesToLong(sessionIDBytes))
    {
        System.out.println("Session id's do not match! Aborting...");
        return false;
    }
    byte[] nonceBytes = deserializeItem(decrResponse, offset);
    offset += nonceBytes.length;
    offset += Integer.BYTES;

    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    byteArrayOutputStream.write(decrResponse, offset, decrResponse.length - offset);
    byte[] encrSignature = byteArrayOutputStream.toByteArray();

    byteArrayOutputStream.reset();
    byteArrayOutputStream.write(responseBytes);
    byteArrayOutputStream.write(sessionIDBytes);
    byteArrayOutputStream.write(doubleToBytes(this.amount));
    byteArrayOutputStream.write(nonceBytes);
    byte[] toCompare = byteArrayOutputStream.toByteArray();

    if (!checkSignature(encrSignature, merchantPubKey, toCompare))
    {
        System.out.println("Signatures do not match! Aborting...");
        return false;
    }
    return true;
}

private boolean initMerchantConnection(String address)
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

private boolean initPgConnection(String address)
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
        outputStream.write(intToBytes(piToSign.length));
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

private boolean receiveResponseFromMerchant() throws IOException, ClassNotFoundException, InvalidKeyException,
        BadPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, NoSuchPaddingException
{
    byte[] encrResponse = (byte[]) this.client2MerchantInput.readObject();
    byte[] decrResponse = client2MerchantSymKeysInfr.decryptMessage(encrResponse);
    return deserializePayloadFromMerchant(decrResponse);
}

private boolean receiveSession() throws ClassNotFoundException, IOException, NoSuchPaddingException,
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

private boolean sendCommandInfo(String cardNumber, String expDate, String pin, double amount, String merchantName,
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

public static void main(String[] args) throws IOException, ClassNotFoundException, IllegalBlockSizeException,
        InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException
{
    String address = "127.0.0.1";
    Client client = new Client();
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