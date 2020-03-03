package communication;

import crypto.AsymKeysInfrastructure;
import crypto.SymKeysInfrastructure;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.net.*;
import java.io.*;
import java.nio.ByteBuffer;
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
            this.client2MerchantOutput.writeObject(clientSymKeyInfr.encryptMessage(ACKNOWLEDGE_CLIENT.getBytes()));
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
        this.paymentGatewayPubKey = (PublicKey) merchant2GatewayInput.readObject();

        // client -> merchant : clientPubKey
        this.merchant2GatewayOutput = new ObjectOutputStream(this.merchant2GatewaySocket.getOutputStream());
        merchant2GatewayOutput.writeObject(this.asymKeysInfr.getPublicKey());

        // client -> merchant: {clientSymmetricKey}merchantPubKey
        byte[] encrCustomerSymKey = asymKeysInfr.encryptDecryptMessage(merchantSymKeyInfr.getSecretKey().getEncoded(), Cipher.ENCRYPT_MODE, paymentGatewayPubKey, null);
        merchant2GatewayOutput.writeObject(encrCustomerSymKey);

        // merchant -> client: {acknowledgement}clientSymmetricKey
        byte[] encrAcknowledge = (byte[]) merchant2GatewayInput.readObject();
        byte[] acknowledge = merchantSymKeyInfr.decryptMessage(encrAcknowledge);
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
            ByteBuffer byteBuffer = ByteBuffer.allocate(SIZE_OF_INT);
            byteBuffer.put(commandInfo, 0, SIZE_OF_INT);
            offset += SIZE_OF_INT;
            int pmLength = bytesToInt(byteBuffer.array());

            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            byteArrayOutputStream.write(commandInfo, offset, pmLength);
            offset += pmLength;
            byte[] pm = byteArrayOutputStream.toByteArray();

            byteArrayOutputStream.reset();
            byteArrayOutputStream.write(commandInfo, offset + 1, commandInfo.length - offset - 1);
            byte[] po = byteArrayOutputStream.toByteArray();
            deserializePO(po);
            return true;
        }
        catch (IOException | ClassNotFoundException excp)
        {
            excp.printStackTrace();
            return false;
        }
    }

    private boolean deserializePO(byte[] po)
    {
        ByteBuffer byteBuffer = ByteBuffer.allocate(SIZE_OF_INT);
        byteBuffer.put(po, 0, SIZE_OF_INT);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        int orderDescSize = bytesToInt(byteBuffer.array());
        int offset = SIZE_OF_INT;
        outputStream.write(po, offset, orderDescSize);
        byte[] orderDesc = outputStream.toByteArray();
        offset += orderDesc.length;


        byteBuffer = ByteBuffer.allocate(SIZE_OF_INT);
        byteBuffer.put(po, offset, SIZE_OF_INT);
        long sessionIDSize = bytesToInt(byteBuffer.array());
        offset += SIZE_OF_INT;
        outputStream.reset();
        outputStream.write(po, offset, (int) sessionIDSize);
        byte[] sessionIDBytes = outputStream.toByteArray();
        long sessionId = bytesToLong(sessionIDBytes);
        offset += sessionIDBytes.length;

        byteBuffer = ByteBuffer.allocate(SIZE_OF_INT);
        byteBuffer.put(po, offset, SIZE_OF_INT);
        long amountSize = bytesToInt(byteBuffer.array());
        offset += SIZE_OF_INT;
        outputStream.reset();
        outputStream.write(po, offset, (int) amountSize);
        byte[] amountBytes = outputStream.toByteArray();
        double amount = bytesToDouble(amountBytes);

        return true;
    }

    public boolean deserializePM()
    {
        return true;
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
        // starts server and waits for a connection
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
            throw new ExceptionInInitializerError("Couldn't deserialize the command information correctly!");
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