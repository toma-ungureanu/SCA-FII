package communication;

import crypto.AsymKeysInfrastructure;
import crypto.SymKeysInfrastructure;
import org.javatuples.Pair;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.net.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
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
    private static final int SIZE_OF_INT = 4;

    private ServerSocket merchantServer;

    private Socket clientMerchantSocket;
    private Socket merchant2GatewaySocket;

    private ObjectInputStream client2MerchantInput;
    private ObjectInputStream merchant2GatewayInput;

    private ObjectOutputStream client2MerchantOutput;
    private ObjectOutputStream merchant2GatewayOutput;

    private AsymKeysInfrastructure asymKeysInfr;
    private SymKeysInfrastructure clientSymKeyInfr;
    private SymKeysInfrastructure merchantSymKeyInfr;

    private PublicKey paymentGatewayPubKey;
    private PublicKey clientPubKey;

    public boolean client2MerchantHandshake()
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
            this.clientSymKeyInfr = new SymKeysInfrastructure(new SecretKeySpec(decrCustomerSymKey, "AES"));

            //merchant -> client: {acknowledgement}clientSymmetricKey
            this.client2MerchantOutput.writeObject(this.clientSymKeyInfr.encryptMessage(ACKNOWLEDGE_CLIENT.getBytes()));
            return true;
        }
        catch (IOException | ClassNotFoundException | InvalidKeyException | NoSuchAlgorithmException |
                NoSuchPaddingException | InvalidAlgorithmParameterException exception)
        {
            exception.printStackTrace();
            return false;
        }
    }

    public boolean merchant2PaymentGatewayHandshake() throws IOException, ClassNotFoundException
    {
        // merchant -> client : merchantPubKey
        this.merchant2GatewayInput = new ObjectInputStream(this.merchant2GatewaySocket.getInputStream());
        this.paymentGatewayPubKey = (PublicKey) this.merchant2GatewayInput.readObject();

        // client -> merchant : clientPubKey
        this.merchant2GatewayOutput = new ObjectOutputStream(this.merchant2GatewaySocket.getOutputStream());
        this.merchant2GatewayOutput.writeObject(this.asymKeysInfr.getPublicKey());

        // client -> merchant: {clientSymmetricKey}merchantPubKey
        byte[] encrCustomerSymKey = this.asymKeysInfr.encryptDecryptMessage(this.merchantSymKeyInfr.getSecretKey().getEncoded(), Cipher.ENCRYPT_MODE, this.paymentGatewayPubKey, null);
        merchant2GatewayOutput.writeObject(encrCustomerSymKey);

        // merchant -> client: {acknowledgement}clientSymmetricKey
        byte[] encrAcknowledge = (byte[]) this.merchant2GatewayInput.readObject();
        byte[] acknowledge = this.merchantSymKeyInfr.decryptMessage(encrAcknowledge);
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

    private boolean receiveCommandInfo()
    {
        try
        {
            byte[] encrCommandInfo = (byte[]) this.client2MerchantInput.readObject();
            byte[] commandInfo = this.clientSymKeyInfr.decryptMessage(encrCommandInfo);

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

            if (!send2Pg(pm, sessionId, amount))
            {
                System.out.println("Couldn't send the command further to the payment gateway!");
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

    private boolean send2Pg(byte[] pm, byte[] sessionId, byte[] amount)
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
            this.merchant2GatewayOutput.writeObject(this.merchantSymKeyInfr.encryptMessage(byteArrayOutputStream.toByteArray()));
            return true;
        }
        catch (IOException | NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException |
                BadPaddingException | IllegalBlockSizeException exception)
        {
            exception.printStackTrace();
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

        byteBuffer = ByteBuffer.allocate(Integer.BYTES);
        byteBuffer.put(po, offset, Integer.BYTES);
        offset += Integer.BYTES;
        int orderDescSize = bytesToInt(byteBuffer.array());
        outputStream.write(po, offset, orderDescSize);
        byte[] orderDesc = outputStream.toByteArray();
        offset += orderDesc.length;

        byteBuffer = ByteBuffer.allocate(Integer.BYTES);
        byteBuffer.put(po, offset, Integer.BYTES);
        int sessionIDSize = bytesToInt(byteBuffer.array());
        offset += Integer.BYTES;
        outputStream.reset();
        outputStream.write(po, offset, sessionIDSize);
        byte[] sessionIDBytes = outputStream.toByteArray();
        long sessionId = bytesToLong(sessionIDBytes);

        offset += sessionIDBytes.length;
        byteBuffer = ByteBuffer.allocate(Integer.BYTES);
        byteBuffer.put(po, offset, Integer.BYTES);
        int amountSize = bytesToInt(byteBuffer.array());
        offset += Integer.BYTES;
        outputStream.reset();
        outputStream.write(po, offset, amountSize);
        byte[] amountBytes = outputStream.toByteArray();
        double amount = bytesToDouble(amountBytes);

        offset += amountBytes.length;
        byteBuffer = ByteBuffer.allocate(Integer.BYTES);
        byteBuffer.put(po, offset, Integer.BYTES);
        int nonceSize = bytesToInt(byteBuffer.array());
        offset += Integer.BYTES;
        outputStream.reset();
        outputStream.write(po, offset, nonceSize);
        byte[] nonceBytes = outputStream.toByteArray();
        long nonce = bytesToLong(nonceBytes);

        offset += nonceBytes.length;
        outputStream.reset();
        outputStream.write(po, offset, po.length - offset);
        byte[] encrSig = outputStream.toByteArray();

        if (!checkPOSig(poSize, orderDescSize, orderDesc, sessionIDSize, sessionIDBytes, amountSize, amountBytes,
                nonceSize, nonceBytes, encrSig))
        {
            System.out.println("Forged signature detected! Aborting...");
            return null;
        }

        return new Pair<>(sessionIDBytes, amountBytes);
    }

    private boolean checkPOSig(int poSize, int orderDescSize, byte[] orderDesc, int sessionIdSize, byte[] sessionIdBytes,
                               int amountSize, byte[] amountBytes, int nonceSize, byte[] nonceBytes, byte[] encrSig)
    {
        try
        {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(intToBytes(poSize));

            outputStream.write(intToBytes(orderDescSize));
            outputStream.write(orderDesc);

            outputStream.write(intToBytes(sessionIdSize));
            outputStream.write(sessionIdBytes);

            outputStream.write(intToBytes(amountSize));
            outputStream.write(amountBytes);

            outputStream.write(intToBytes(nonceSize));
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

    public void sendSession() throws NoSuchAlgorithmException, IOException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException
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
        byte[] msgToSend = this.clientSymKeyInfr.encryptMessage(outputStream.toByteArray());
        client2MerchantOutput.writeObject(msgToSend);
    }

    public long generateId()
    {
        ThreadLocalRandom random = ThreadLocalRandom.current();
        return random.nextLong(10_000_000_000L, 100_000_000_000L);
    }

    public Merchant(String address)
    {
        this.asymKeysInfr = new AsymKeysInfrastructure();
        if (!this.asymKeysInfr.loadRSAKeys(PUBLIC_KEY_PATH, PRIVATE_KEY_PATH))
        {
            this.asymKeysInfr.initRSAKeyPairs();
            this.asymKeysInfr.saveKeys(PUBLIC_KEY_PATH, PRIVATE_KEY_PATH);
        }
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

    public boolean initPaymentGatewayConnection(String address)
    {
        try
        {
            this.merchant2GatewaySocket = new Socket(address, MERCHANT_TO_GATEWAY_PORT);
            System.out.println("Merchant started");
            System.out.println("Connected to the payment Gateway!");
            this.merchantSymKeyInfr = new SymKeysInfrastructure(null);
            return true;
        }
        catch (IOException | NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException |
                NoSuchPaddingException exception)
        {
            exception.printStackTrace();
            return false;
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

    public void receiveCommand() throws NoSuchPaddingException, NoSuchAlgorithmException, IOException,
            BadPaddingException, IllegalBlockSizeException, InvalidKeyException
    {
        sendSession();

        if (!receiveCommandInfo())
        {
            throw new ExceptionInInitializerError("An unexpected problem occurred");
        }
        System.out.println("Order received!");
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, IllegalBlockSizeException,
            InvalidKeyException, BadPaddingException, NoSuchPaddingException, ClassNotFoundException
    {
        String address = "127.0.0.1";
        Merchant merchant = new Merchant(address);
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