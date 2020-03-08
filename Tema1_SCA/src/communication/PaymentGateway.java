package communication;

import crypto.AsymKeysInfrastructure;
import crypto.SymKeysInfrastructure;
import javafx.util.Pair;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import static utils.Utils.*;

public class PaymentGateway
{
private static final int MERCHANT_TO_GATEWAY_PORT = 50000;
private static final int CLIENT_TO_GATEWAY_PORT = 60000;
private static final String ACKNOWLEDGE_MERCHANT = "Ready for communication!" + MERCHANT_TO_GATEWAY_PORT;
private static final String ACKNOWLEDGE_CLIENT = "Ready for communication!" + CLIENT_TO_GATEWAY_PORT;
private static final String PRIVATE_KEY_PATH = "\\payment_gateway_keys\\privateKey.key";
private static final String PUBLIC_KEY_PATH = "\\payment_gateway_keys\\publicKey.pub";
private static final String RESPONSE = "Command has been processed successfully!";

private AsymKeysInfrastructure asymKeysInfr;
private Socket client2PgSocket;
private SymKeysInfrastructure client2PgSymKeysInfr;
private PublicKey clientPubKey;
private ObjectInputStream merchant2pgInput;
private ObjectOutputStream merchant2pgOutput;
private Socket merchant2PgSocket;
private SymKeysInfrastructure merchant2PgSymKeysInfr;
private PublicKey merchantPubKey;

public PaymentGateway()
{
    this.asymKeysInfr = new AsymKeysInfrastructure();
    if (!this.asymKeysInfr.loadRSAKeys(PUBLIC_KEY_PATH, PRIVATE_KEY_PATH))
    {
        this.asymKeysInfr.initRSAKeyPairs();
        this.asymKeysInfr.saveKeys(PUBLIC_KEY_PATH, PRIVATE_KEY_PATH);
    }

    try
    {
        this.client2PgSymKeysInfr = new SymKeysInfrastructure(null);
        this.merchant2PgSymKeysInfr = new SymKeysInfrastructure(null);
    }
    catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException |
            InvalidAlgorithmParameterException exception)
    {
        exception.printStackTrace();
    }
}

public boolean connect() throws IOException, ClassNotFoundException
{
    if (!initMerchantConnection())
    {
        System.out.println("Error while initializing connection with merchant!");
        return false;
    }

    if (!pg2MerchantHandshake())
    {
        System.out.println("Error while initializing connection with merchant!");
        return false;
    }

    if (!(initClientConnection()))
    {
        System.out.println("Error while initializing connection with client!");
        return false;
    }

    if (!pg2ClientHandshake())
    {
        System.out.println("Error while initializing connection with payment gateway!");
        return false;
    }
    return true;
}

public boolean commandFlow()
{
    try
    {
        Pair<byte[], byte[]> sessionID_amount = deserializePaymentInfo(receiveCommand());
        if (sessionID_amount == null)
        {
            return false;
        }
        sendResponse2Merchant(sessionID_amount);
        return true;
    }
    catch (IOException | ClassNotFoundException e)
    {
        e.printStackTrace();
        return false;
    }
}

private boolean checkInfo(String cardN, String cardExp, String pin, byte[] sessionID, byte[] clientReceivedPubKey,
                          byte[]amount, byte[] encrSig, byte[] nonce, byte[] merchantName)
        throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, IOException
{
    if (!checkCard(cardN, cardExp, pin))
    {
        System.out.println("Card Information incorrect!");
        return false;
    }

    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    //card number
    byteArrayOutputStream.write(intToBytes(cardN.getBytes().length));
    byteArrayOutputStream.write(cardN.getBytes());
    //card expiration date
    byteArrayOutputStream.write(intToBytes(cardExp.getBytes().length));
    byteArrayOutputStream.write(cardExp.getBytes());
    //pin
    byteArrayOutputStream.write(intToBytes(pin.length()));
    byteArrayOutputStream.write(pin.getBytes());
    //session id
    byteArrayOutputStream.write(intToBytes(Long.BYTES));
    byteArrayOutputStream.write(sessionID);
    //amount
    byteArrayOutputStream.write(intToBytes(Double.BYTES));
    byteArrayOutputStream.write(amount);
    //client pubkey
    byteArrayOutputStream.write(intToBytes(clientReceivedPubKey.length));
    byteArrayOutputStream.write(clientReceivedPubKey);
    //nonce
    byteArrayOutputStream.write(intToBytes(Long.BYTES));
    byteArrayOutputStream.write(nonce);
    //merchant name
    byteArrayOutputStream.write(intToBytes(merchantName.length));
    byteArrayOutputStream.write(merchantName);

    byte[] toCompare = byteArrayOutputStream.toByteArray();
    if (!checkSignature(encrSig, clientPubKey, toCompare))
    {
        System.out.println("Signatures don't match!");
        return false;
    }
    return true;
}

private Pair<byte[], byte[]> deserializePaymentInfo(byte[] decrPaymentInfo)
{
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    ByteBuffer byteBuffer = ByteBuffer.allocate(Integer.BYTES);
    byteBuffer.put(decrPaymentInfo, 0, Integer.BYTES);
    int pmLength = bytesToInt(byteBuffer.array());
    int offset = Integer.BYTES;
    byteArrayOutputStream.write(decrPaymentInfo, offset, pmLength);
    offset += pmLength;
    byte[] encrPm = byteArrayOutputStream.toByteArray();
    byte[] decrPm = this.client2PgSymKeysInfr.decryptMessage(encrPm);

    byteArrayOutputStream.reset();
    byteArrayOutputStream.write(decrPaymentInfo, offset, decrPaymentInfo.length - offset);
    byte[] merchantSignature = byteArrayOutputStream.toByteArray();
    return deserializePM(decrPm, merchantSignature);
}

private Pair<byte[], byte[]> deserializePM(byte[] pm, byte[] merchantSignature)
{
    int offset = 0;
    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    byte[] pi = deserializeItem(pm, offset);
    offset += pi.length;
    offset += Integer.BYTES;

    byteArrayOutputStream.write(pm, offset, pm.length - offset);
    byte[] clientSignature = byteArrayOutputStream.toByteArray();

    //card number
    offset = 0;
    byte[] cardN = deserializeItem(pi, 0);
    offset += cardN.length;
    offset += Integer.BYTES;

    //card expDate
    byte[] cardExp = deserializeItem(pi, offset);
    offset += cardExp.length;
    offset += Integer.BYTES;

    //card pin
    byte[] pin = deserializeItem(pi, offset);
    offset += pin.length;
    offset += Integer.BYTES;

    //session id
    byte[] sessionID = deserializeItem(pi, offset);
    offset += sessionID.length;
    offset += Integer.BYTES;

    //amount
    byte[] amountBytes = deserializeItem(pi, offset);
    offset += amountBytes.length;
    offset += Integer.BYTES;
    double amount = bytesToDouble(amountBytes);

    //client pub key
    byte[] clientReceivedPubKey = deserializeItem(pi,offset);
    offset += clientReceivedPubKey.length;
    offset += Integer.BYTES;

    byte[] authClientPubKey = clientPubKey.getEncoded();
    if (clientReceivedPubKey.length != authClientPubKey.length)
    {
        System.out.println("Incorrect public key size!");
        return null;
    }

    for (int i = 0; i < clientReceivedPubKey.length; i++)
    {
        if (clientReceivedPubKey[i] != authClientPubKey[i])
        {
            System.out.println("Incorrect public keys!");
            return null;
        }
    }

    //nonce
    byte[] nonce = deserializeItem(pi,offset);
    offset += nonce.length;
    offset += Integer.BYTES;

    //merchant name
    byte[] merchantName = deserializeItem(pi, offset);
    try
    {
        if(!checkInfo(new String(cardN, StandardCharsets.UTF_8), new String(cardExp, StandardCharsets.UTF_8), new String(pin, StandardCharsets.UTF_8), sessionID,
                clientReceivedPubKey, amountBytes, clientSignature, nonce, merchantName))
        {
            return null;
        }

        byteArrayOutputStream.reset();
        byteArrayOutputStream.write(sessionID);
        byteArrayOutputStream.write(this.clientPubKey.getEncoded());
        byteArrayOutputStream.write(amountBytes);
        byte[] merchantToCompare = byteArrayOutputStream.toByteArray();
        if (!checkSignature(merchantSignature, this.merchantPubKey, merchantToCompare))
        {
            return null;
        }
        return new Pair<>(sessionID, amountBytes);
    }
    catch (IOException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException |
            BadPaddingException | IllegalBlockSizeException excp)
    {
        excp.printStackTrace();
        return null;
    }
}


private boolean initClientConnection()
{
    try
    {
        ServerSocket client2PgServer = new ServerSocket(CLIENT_TO_GATEWAY_PORT);
        System.out.println("\nWaiting for client ...");

        //initialize socket and input stream
        this.client2PgSocket = client2PgServer.accept();
        System.out.println("Client accepted");

        return true;
    }
    catch(IOException exception)
    {
        exception.printStackTrace();
        return false;
    }
}

private boolean initMerchantConnection()
{
    // starts server and waits for a connection
    try
    {
        ServerSocket merchant2PgServer = new ServerSocket(MERCHANT_TO_GATEWAY_PORT);
        System.out.println("Payment Gateway started");
        System.out.println("\nWaiting for merchant ...");

        //initialize socket and input stream
        this.merchant2PgSocket = merchant2PgServer.accept();
        System.out.println("Merchant accepted");

        return true;
    }
    catch(IOException exception)
    {
        exception.printStackTrace();
        return false;
    }
}

private boolean pg2ClientHandshake()
{
    try
    {
        // payment gateway -> client : payment gateway PubKey
        ObjectOutputStream client2PgOutput = new ObjectOutputStream(this.client2PgSocket.getOutputStream());
        client2PgOutput.writeObject(this.asymKeysInfr.getPublicKey());

        // client -> payment gateway : clientPubKey
        ObjectInputStream client2PgInput = new ObjectInputStream(this.client2PgSocket.getInputStream());
        this.clientPubKey = (PublicKey) client2PgInput.readObject();

        // client -> payment gateway: {clientSymmetricKey}merchantPubKey
        byte[] encrCustomerSymKey = (byte[]) client2PgInput.readObject();
        byte[] decrCustomerSymKey = this.asymKeysInfr.encryptDecryptMessage(encrCustomerSymKey, Cipher.DECRYPT_MODE, null, null);
        this.client2PgSymKeysInfr = new SymKeysInfrastructure(new SecretKeySpec(decrCustomerSymKey, "AES"));

        // payment gateway -> client: {acknowledgement}clientSymmetricKey
        client2PgOutput.writeObject(client2PgSymKeysInfr.encryptMessage(ACKNOWLEDGE_CLIENT.getBytes()));
        return true;
    }
    catch (IOException | ClassNotFoundException | InvalidKeyException | NoSuchAlgorithmException |
            NoSuchPaddingException | InvalidAlgorithmParameterException exception)
    {
        exception.printStackTrace();
        return false;
    }
}

private boolean pg2MerchantHandshake()
{
    try
    {
        // merchant -> client: merchant public key
        this.merchant2pgOutput = new ObjectOutputStream(this.merchant2PgSocket.getOutputStream());
        this.merchant2pgOutput.writeObject(asymKeysInfr.getPublicKey());

        // client -> merchant: client public key
        this.merchant2pgInput = new ObjectInputStream(this.merchant2PgSocket.getInputStream());
        this.merchantPubKey = (PublicKey) this.merchant2pgInput.readObject();

        // client -> merchant: {clientSymmetricKey}merchantPubKey
        byte[] encrMerchantSymKey = (byte[]) this.merchant2pgInput.readObject();
        byte[] decrMerchantSymKey = this.asymKeysInfr.encryptDecryptMessage(encrMerchantSymKey, Cipher.DECRYPT_MODE, null, null);
        this.merchant2PgSymKeysInfr = new SymKeysInfrastructure(new SecretKeySpec(decrMerchantSymKey, "AES"));

        //merchant -> client: {acknowledgement}clientSymmetricKey
        this.merchant2pgOutput.writeObject(merchant2PgSymKeysInfr.encryptMessage(ACKNOWLEDGE_MERCHANT.getBytes()));
        return true;
    }
    catch (IOException | ClassNotFoundException | InvalidKeyException | NoSuchAlgorithmException |
            NoSuchPaddingException | InvalidAlgorithmParameterException exception)
    {
        exception.printStackTrace();
        return false;
    }
}

private byte[] receiveCommand() throws IOException, ClassNotFoundException
{
    byte[] encrPaymentInfo = (byte[]) this.merchant2pgInput.readObject();
    return this.merchant2PgSymKeysInfr.decryptMessage(encrPaymentInfo);
}

private void sendResponse2Merchant( Pair<byte[], byte[]> sessionID_amount)
{
    try
    {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.reset();
        //response
        byteArrayOutputStream.write(RESPONSE.getBytes());
        //session id
        byteArrayOutputStream.write(sessionID_amount.getKey());
        //amount
        byteArrayOutputStream.write(sessionID_amount.getValue());
        //nonce
        long nonce = generateNonce();
        byteArrayOutputStream.write(longToBytes(nonce));
        byte[] signature = generateSignature(byteArrayOutputStream.toByteArray(), this.asymKeysInfr.getPrivateKey());

        byteArrayOutputStream.reset();
        //response length, response
        byteArrayOutputStream.write(intToBytes(RESPONSE.length()));
        byteArrayOutputStream.write(RESPONSE.getBytes());
        //sessionID length, sessionID
        byteArrayOutputStream.write(intToBytes(sessionID_amount.getKey().length));
        byteArrayOutputStream.write(sessionID_amount.getKey());
        //nonce
        byteArrayOutputStream.write(intToBytes(Long.BYTES));
        byteArrayOutputStream.write(longToBytes(nonce));
        //signature
        byteArrayOutputStream.write(signature);
        byte[] encrToSend = merchant2PgSymKeysInfr.encryptMessage(byteArrayOutputStream.toByteArray());
        merchant2pgOutput.writeObject(encrToSend);
    }
    catch (IOException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException |
            BadPaddingException | IllegalBlockSizeException excp)
    {
        excp.printStackTrace();
    }
}

public static void main(String[] args) throws IOException, ClassNotFoundException
{
    PaymentGateway paymentGateway = new PaymentGateway();

    boolean flag = false;
    while(true)
    {
        if(!flag)
        {
            flag = paymentGateway.connect();
            if (!paymentGateway.commandFlow())
            {
                System.out.println("Command processing failed!");
            }
        }
    }
}
}
