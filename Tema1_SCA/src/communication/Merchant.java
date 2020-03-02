package communication;

import crypto.AsymKeysInfrastructure;
import crypto.SymKeysInfrastructure;
import org.jetbrains.annotations.NotNull;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.net.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.concurrent.ThreadLocalRandom;

import static utils.Utils.generateSignature;

public class Merchant
{
    private static final String PRIVATE_KEY_PATH = "\\merchant_keys\\privateKey.key";
    private static final String PUBLIC_KEY_PATH = "\\merchant_keys\\publicKey.pub";
    private static final int MERCHANT_TO_CLIENT_PORT = 50000;
    private static final String ACKNOWLEDGE = "Ready for communication!" + MERCHANT_TO_CLIENT_PORT;
    private static final int MERCHANT_TO_GATEWAY_PORT = 60000;

    private ServerSocket merchantServer;
    private Socket clientMerchantSocket;
    private Socket merchant2GatewaySocket;
    private ObjectInputStream client2MerchantInput;
    private ObjectOutputStream merchant2ClientOutput;
    private ObjectInputStream merchant2GatewayInput;
    private ObjectOutputStream merchant2GatewayOutput;
    private AsymKeysInfrastructure asymKeysInfr;
    private SymKeysInfrastructure clientSymKeyInfr;
    private PublicKey paymentGatewayPubKey;
    private PublicKey clientPubKey;

    public boolean client2MerchantHandshake()
    {
        try
        {
            // merchant -> client: merchantPubKey
            this.merchant2ClientOutput = new ObjectOutputStream(this.clientMerchantSocket.getOutputStream());
            this.merchant2ClientOutput.writeObject(asymKeysInfr.getPublicKey());

            // client -> merchant: clientPubKey
            this.client2MerchantInput = new ObjectInputStream(this.clientMerchantSocket.getInputStream());
            this.clientPubKey = (PublicKey) this.client2MerchantInput.readObject();

            // client -> merchant: {clientSymmetricKey}merchantPubKey
            byte[] encrCustomerSymKey = (byte[]) this.client2MerchantInput.readObject();
            byte[] decrCustomerSymKey = this.asymKeysInfr.encryptDecryptMessage(encrCustomerSymKey, Cipher.DECRYPT_MODE, null, null);
            this.clientSymKeyInfr = new SymKeysInfrastructure(new SecretKeySpec(decrCustomerSymKey, "AES"));

            //merchant -> client: {acknowledgement}clientSymmetricKey
            this.merchant2ClientOutput.writeObject(clientSymKeyInfr.encryptMessage(ACKNOWLEDGE.getBytes()));
            return true;
        }
        catch (IOException | ClassNotFoundException | InvalidKeyException | NoSuchAlgorithmException |
                NoSuchPaddingException | InvalidAlgorithmParameterException exception)
        {
            exception.printStackTrace();
            return false;
        }
    }

    public boolean merchant2PaymentGatewayHandshake()
    {
        try
        {
            // merchant -> client: merchantPubkey
            this.merchant2GatewayOutput = new ObjectOutputStream(this.merchant2GatewaySocket.getOutputStream());
            this.merchant2GatewayOutput.writeObject(asymKeysInfr.getPublicKey());

            return true;
        }
        catch (IOException e)
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
        merchant2ClientOutput.writeObject(msgToSend);
    }

    public long generateId()
    {
        ThreadLocalRandom random = ThreadLocalRandom.current();
        return random.nextLong(10_000_000_000L, 100_000_000_000L);
    }

    public Merchant(String address)
    {
//        if(!initPaymentGatewayConnection(address))
//        {
//            throw new ExceptionInInitializerError();
//        }

        if (!initClientConnection())
        {
            throw new ExceptionInInitializerError();
        }

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
            System.out.println("Merchant started");
            System.out.println("Waiting for a client ...");

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
            System.out.println("Connected to the payment Gateway!");
            return true;
        }
        catch (IOException exception)
        {
            exception.printStackTrace();
            return false;
        }
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, IllegalBlockSizeException,
            InvalidKeyException, BadPaddingException, NoSuchPaddingException
    {
        String address = "127.0.0.1";
        Merchant merchant = new Merchant(address);
        if (!merchant.client2MerchantHandshake())
        {
            System.out.println("Cannot proceed, communication handshake failed!");
        }
        merchant.sendSession();
    }
} 