package communication;

import crypto.AsymKeysInfrastructure;
import crypto.SymKeysInfrastructure;
import org.javatuples.Pair;

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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;

import static utils.Utils.*;

public class Merchant
{
private static final String PRIVATE_KEY_PATH = "\\merchant_keys\\privateKey.key";
private static final String PUBLIC_KEY_PATH = "\\merchant_keys\\publicKey.pub";
private static final int MERCHANT_TO_CLIENT_PORT = 40000;
private static final int MERCHANT_TO_GATEWAY_PORT = 50000;
private static final String ACKNOWLEDGE_CLIENT = "Ready for communication!" + MERCHANT_TO_CLIENT_PORT;
private static final String ACKNOWLEDGE_GATEWAY = "Ready for communication!" + MERCHANT_TO_GATEWAY_PORT;

private ServerSocket merchantServer;

private Socket clientMerchantSocket;
private Socket merchant2GatewaySocket;

private ObjectInputStream client2MerchantInput;
private ObjectInputStream merchant2GatewayInput;

private ObjectOutputStream client2MerchantOutput;
private ObjectOutputStream merchant2GatewayOutput;

private AsymKeysInfrastructure asymKeysInfr;
private SymKeysInfrastructure client2MerchantSymKeyInfr;
private SymKeysInfrastructure merchant2PgSymKeyInfr;

private PublicKey paymentGatewayPubKey;
private PublicKey clientPubKey;

double amount;

public Merchant()
{
    this.asymKeysInfr = new AsymKeysInfrastructure();
    if (!this.asymKeysInfr.loadRSAKeys(PUBLIC_KEY_PATH, PRIVATE_KEY_PATH))
    {
        this.asymKeysInfr.initRSAKeyPairs();
        this.asymKeysInfr.saveKeys(PUBLIC_KEY_PATH, PRIVATE_KEY_PATH);
    }
}

public boolean connect(String address) throws IOException, ClassNotFoundException
{
    if (!initPaymentGatewayConnection(address))
    {
        System.out.println("Error while initializing connection with the payment gateway!");
        return false;
    }

    if (!merchant2PaymentGatewayHandshake())
    {
        System.out.println("Error while initializing connection with the payment gateway!");
        return false;
    }

    if (!initClientConnection())
    {
        System.out.println("Error while initializing connection with the client!");
        return false;
    }

    if (!client2MerchantHandshake())
    {
        System.out.println("Cannot proceed, communication handshake failed!");
        return false;
    }
    return true;
}

private boolean client2MerchantHandshake()
{
    try
    {
        // merchant -> client: merchant public key
        this.client2MerchantOutput = new ObjectOutputStream(this.clientMerchantSocket.getOutputStream());
        this.client2MerchantOutput.writeObject(asymKeysInfr.getPublicKey());

        // client -> merchant: client public key
        this.client2MerchantInput = new ObjectInputStream(this.clientMerchantSocket.getInputStream());
        this.clientPubKey = (PublicKey) this.client2MerchantInput.readObject();

        // client -> merchant: {clientSymmetricKey}merchantPubKey
        byte[] encrCustomerSymKey = (byte[]) this.client2MerchantInput.readObject();
        byte[] decrCustomerSymKey = this.asymKeysInfr.encryptDecryptMessage(encrCustomerSymKey, Cipher.DECRYPT_MODE, null, null);
        this.client2MerchantSymKeyInfr = new SymKeysInfrastructure(new SecretKeySpec(decrCustomerSymKey, "AES"));

        //merchant -> client: {acknowledgement}clientSymmetricKey
        this.client2MerchantOutput.writeObject(this.client2MerchantSymKeyInfr.encryptMessage(ACKNOWLEDGE_CLIENT.getBytes()));
        return true;
    }
    catch (IOException | ClassNotFoundException | InvalidKeyException | NoSuchAlgorithmException |
            NoSuchPaddingException | InvalidAlgorithmParameterException exception)
    {
        exception.printStackTrace();
        return false;
    }
}

private boolean commandFlow()
{
    try
    {
        byte[] encrCommandInfo = (byte[]) this.client2MerchantInput.readObject();
        byte[] commandInfo = this.client2MerchantSymKeyInfr.decryptMessage(encrCommandInfo);

        int offset = 0;
        ByteBuffer byteBuffer = ByteBuffer.allocate(Integer.BYTES);
        byteBuffer.put(commandInfo, 0, Integer.BYTES);
        offset += Integer.BYTES;
        int pmLength = bytesToInt(byteBuffer.array());

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.write(commandInfo, offset, pmLength);
        offset += pmLength;
        byte[] pm = byteArrayOutputStream.toByteArray();

        byteArrayOutputStream.reset();
        byteArrayOutputStream.write(commandInfo, offset + 1, commandInfo.length - offset - 1);
        byte[] po = byteArrayOutputStream.toByteArray();

        Pair<byte[], byte[]> pair = deserializePO(po);
        if (pair == null)
        {
            return false;
        }

        byte[] sessionId = pair.getValue0();
        byte[] amount = pair.getValue1();

        if (!sendCommand2Pg(pm, sessionId, amount))
        {
            System.out.println("Couldn't send the command further to the payment gateway!");
            return false;
        }

        pair = receiveResponseFromPg();
        if (pair == null)
        {
            System.out.println("Couldn't deserialize the response!");
            return false;
        }

        byte[] responseBytes = pair.getValue0();
        byte[] sessionIdBytes = pair.getValue1();
        if (!sendResponseToClient(responseBytes, sessionIdBytes))
        {
            System.out.println("Couldn't send the response to the client!");
            return false;
        }

        return true;
    }
    catch (IOException | ClassNotFoundException excp)
    {
        excp.printStackTrace();
        return false;
    }
}

private boolean checkPOSig(int poSize, byte[] orderDesc, byte[] sessionIdBytes, byte[] amountBytes, byte[] nonceBytes, byte[] encrSig)
{
    try
    {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(intToBytes(poSize));

        outputStream.write(intToBytes(orderDesc.length));
        outputStream.write(orderDesc);

        outputStream.write(intToBytes(sessionIdBytes.length));
        outputStream.write(sessionIdBytes);

        outputStream.write(intToBytes(amountBytes.length));
        outputStream.write(amountBytes);

        outputStream.write(intToBytes(nonceBytes.length));
        outputStream.write(nonceBytes);

        byte[] po = outputStream.toByteArray();

        return checkSignature(encrSig, this.clientPubKey, po);
    }
    catch (IOException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e)
    {
        e.printStackTrace();
        return false;
    }

}

private Pair<byte[], byte[]> deserializePO(byte[] po)
{
    ByteBuffer byteBuffer = ByteBuffer.allocate(Integer.BYTES);
    byteBuffer.put(po, 0, Integer.BYTES);
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    int poSize = bytesToInt(byteBuffer.array());

    int offset = Integer.BYTES;
    byte[] orderDesc = deserializeItem(po, offset);

    offset += Integer.BYTES;
    offset += orderDesc.length;
    byte[] sessionIDBytes = deserializeItem(po, offset);

    offset += Integer.BYTES;
    offset += sessionIDBytes.length;
    byte[] amountBytes = deserializeItem(po, offset);
    this.amount = bytesToDouble(amountBytes);

    offset += Integer.BYTES;
    offset += amountBytes.length;
    byte[] nonceBytes = deserializeItem(po, offset);

    offset += Integer.BYTES;
    offset += nonceBytes.length;
    outputStream.reset();
    outputStream.write(po, offset, po.length - offset);
    byte[] encrSig = outputStream.toByteArray();

    if (!checkPOSig(poSize, orderDesc, sessionIDBytes, amountBytes, nonceBytes, encrSig))
    {
        System.out.println("Forged signature detected! Aborting...");
        return null;
    }

    return new Pair<>(sessionIDBytes, amountBytes);
}

public long generateId()
{
    ThreadLocalRandom random = ThreadLocalRandom.current();
    return random.nextLong(10_000_000_000L, 100_000_000_000L);
}

private boolean initClientConnection()
{
    try
    {
        this.merchantServer = new ServerSocket(MERCHANT_TO_CLIENT_PORT);
        System.out.println("\nWaiting for a client ...");

        this.clientMerchantSocket = this.merchantServer.accept();
        System.out.println("Client accepted");
        return true;
    }
    catch (IOException exception)
    {
        exception.printStackTrace();
        return false;
    }
}

private boolean initPaymentGatewayConnection(String address)
{
    try
    {
        this.merchant2GatewaySocket = new Socket(address, MERCHANT_TO_GATEWAY_PORT);
        System.out.println("Merchant started");
        System.out.println("Connected to the payment Gateway!");
        this.merchant2PgSymKeyInfr = new SymKeysInfrastructure(null);
        return true;
    }
    catch (IOException | NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException |
            NoSuchPaddingException exception)
    {
        exception.printStackTrace();
        return false;
    }
}

private boolean merchant2PaymentGatewayHandshake() throws IOException, ClassNotFoundException
{
    // merchant -> client : merchantPubKey
    this.merchant2GatewayInput = new ObjectInputStream(this.merchant2GatewaySocket.getInputStream());
    this.paymentGatewayPubKey = (PublicKey) this.merchant2GatewayInput.readObject();

    // client -> merchant : clientPubKey
    this.merchant2GatewayOutput = new ObjectOutputStream(this.merchant2GatewaySocket.getOutputStream());
    this.merchant2GatewayOutput.writeObject(this.asymKeysInfr.getPublicKey());

    // client -> merchant: {clientSymmetricKey}merchantPubKey
    byte[] encrCustomerSymKey = this.asymKeysInfr.encryptDecryptMessage(this.merchant2PgSymKeyInfr.getSecretKey().getEncoded(), Cipher.ENCRYPT_MODE, this.paymentGatewayPubKey, null);
    merchant2GatewayOutput.writeObject(encrCustomerSymKey);

    // merchant -> client: {acknowledgement}clientSymmetricKey
    byte[] encrAcknowledge = (byte[]) this.merchant2GatewayInput.readObject();
    byte[] acknowledge = this.merchant2PgSymKeyInfr.decryptMessage(encrAcknowledge);
    if (Arrays.equals(acknowledge, ACKNOWLEDGE_GATEWAY.getBytes()))
    {
        System.out.println("Communication between merchant and payment gateway is secure, you can proceed!");
        return true;
    }
    else
    {
        return false;
    }
}

private Pair<byte[], byte[]> processResponseFromPg(byte[] decrResponse)
{
    try
    {
        int offset = 0;
        byte[] responseBytes = deserializeItem(decrResponse, offset);
        offset += responseBytes.length;
        offset += Integer.BYTES;
        byte[] sessionIdBytes = deserializeItem(decrResponse, offset);
        offset += sessionIdBytes.length;
        offset += Integer.BYTES;
        byte[] nonceBytes = deserializeItem(decrResponse, offset);
        offset += nonceBytes.length;
        offset += Integer.BYTES;

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.write(decrResponse, offset, decrResponse.length - offset);
        byte[] signature = byteArrayOutputStream.toByteArray();

        byteArrayOutputStream.reset();
        byteArrayOutputStream.write(responseBytes);
        byteArrayOutputStream.write(sessionIdBytes);
        byteArrayOutputStream.write(doubleToBytes(this.amount));
        byteArrayOutputStream.write(nonceBytes);

        if (!checkSignature(signature, paymentGatewayPubKey, byteArrayOutputStream.toByteArray()))
        {
            System.out.println("Signatures don't match!");
            return null;
        }

        return new Pair<>(responseBytes, sessionIdBytes);
    }
    catch (IOException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException |
            BadPaddingException | IllegalBlockSizeException e)
    {
        e.printStackTrace();
        return null;
    }
}

private void receiveCommand() throws NoSuchPaddingException, NoSuchAlgorithmException, IOException,
        BadPaddingException, IllegalBlockSizeException, InvalidKeyException
{
    sendSession();

    if (!commandFlow())
    {
        throw new ExceptionInInitializerError("An unexpected problem occurred");
    }
    System.out.println("Order received!");
}

private Pair<byte[], byte[]> receiveResponseFromPg()
{
    try
    {
        byte[] encrResponse = (byte[]) this.merchant2GatewayInput.readObject();
        byte[] decrResponse = this.merchant2PgSymKeyInfr.decryptMessage(encrResponse);
        return processResponseFromPg(decrResponse);
    }
    catch (IOException | ClassNotFoundException exception)
    {
        exception.printStackTrace();
        return null;
    }
}

private boolean sendCommand2Pg(byte[] pm, byte[] sessionId, byte[] amount)
{
    try
    {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.write(sessionId);
        byteArrayOutputStream.write(this.clientPubKey.getEncoded());
        byteArrayOutputStream.write(amount);
        byte[] signature = generateSignature(byteArrayOutputStream.toByteArray(), this.asymKeysInfr.getPrivateKey());

        byteArrayOutputStream.reset();
        byteArrayOutputStream.write(intToBytes(pm.length));
        byteArrayOutputStream.write(pm);
        byteArrayOutputStream.write(signature);
        this.merchant2GatewayOutput.writeObject(this.merchant2PgSymKeyInfr.encryptMessage(byteArrayOutputStream.toByteArray()));
        return true;
    }
    catch (IOException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException |
            BadPaddingException | IllegalBlockSizeException exception)
    {
        exception.printStackTrace();
        return false;
    }
}

private boolean sendResponseToClient(byte[] responseBytes, byte[] sessionIdBytes)
{
    try
    {
        long nonce = generateNonce();
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.write(intToBytes(responseBytes.length));
        byteArrayOutputStream.write(responseBytes);
        byteArrayOutputStream.write(intToBytes(sessionIdBytes.length));
        byteArrayOutputStream.write(sessionIdBytes);
        byteArrayOutputStream.write(intToBytes(Long.BYTES));
        byteArrayOutputStream.write(longToBytes(nonce));
        byte[] resp = byteArrayOutputStream.toByteArray();

        byteArrayOutputStream.reset();
        byteArrayOutputStream.write(responseBytes);
        byteArrayOutputStream.write(sessionIdBytes);
        byteArrayOutputStream.write(doubleToBytes(this.amount));
        byteArrayOutputStream.write(longToBytes(nonce));
        byte[] toSign = byteArrayOutputStream.toByteArray();
        byte[] signature = generateSignature(toSign, asymKeysInfr.getPrivateKey());

        byteArrayOutputStream.reset();
        byteArrayOutputStream.write(resp);
        byteArrayOutputStream.write(signature);
        byte[] toSend = byteArrayOutputStream.toByteArray();
        client2MerchantOutput.writeObject(client2MerchantSymKeyInfr.encryptMessage(toSend));
        return true;
    }
    catch (IOException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e)
    {
        e.printStackTrace();
        return false;
    }
}

private void sendSession() throws NoSuchAlgorithmException, IOException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException
{
    // generate a random 11 digits number
    long sessionID = generateId();

    // convert the number to the byte array
    ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
    buffer.putLong(sessionID);

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    outputStream.write(buffer.array().length);
    outputStream.write(buffer.array());
    outputStream.write(generateSignature(buffer.array(), this.asymKeysInfr.getPrivateKey()));

    // merchant -> client: {sessionID, {hash(sessionID)}merchantPrivKey}clientMerchantAsymKey
    byte[] msgToSend = this.client2MerchantSymKeyInfr.encryptMessage(outputStream.toByteArray());
    client2MerchantOutput.writeObject(msgToSend);
}

public static void main(String[] args) throws IOException, NoSuchAlgorithmException, IllegalBlockSizeException,
        InvalidKeyException, BadPaddingException, NoSuchPaddingException, ClassNotFoundException
{
    String address = "127.0.0.1";
    Merchant merchant = new Merchant();
    boolean flag = false;
    while(true)
    {
        if(!flag)
        {
            flag = merchant.connect(address);
            merchant.receiveCommand();
        }
    }
}
} 