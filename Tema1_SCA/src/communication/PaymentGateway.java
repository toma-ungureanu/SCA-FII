package communication;
import crypto.AsymKeysInfrastructure;
import crypto.SymKeysInfrastructure;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.net.*;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

public class PaymentGateway
{
    private static final int MERCHANT_TO_GATEWAY_PORT = 50000;
    private static final int CLIENT_TO_GATEWAY_PORT = 60000;
    private static final String ACKNOWLEDGE_MERCHANT = "Ready for communication!" + MERCHANT_TO_GATEWAY_PORT;
    private static final String ACKNOWLEDGE_CLIENT = "Ready for communication!" + CLIENT_TO_GATEWAY_PORT;

    private static final String PRIVATE_KEY_PATH = "\\payment_gateway_keys\\privateKey.key";
    private static final String PUBLIC_KEY_PATH = "\\payment_gateway_keys\\publicKey.pub";

    private AsymKeysInfrastructure asymKeysInfr;

    private SymKeysInfrastructure client2PgSymKeysInfr;
    private SymKeysInfrastructure merchant2PgSymKeysInfr;

    private ServerSocket merchant2PgServer;
    private ServerSocket client2PgServer;

    private Socket merchant2PgSocket;
    private Socket client2PgSocket;

    private ObjectInputStream client2PgInput;
    private ObjectOutputStream client2PgOutput;

    private ObjectInputStream merchant2pgInput;
    private ObjectOutputStream merchant2pgOutput;

    private PublicKey clientPubKey;
    private PublicKey merchantPubKey;

    public PaymentGateway(String address)
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

    public boolean initMerchantConnection()
    {
        // starts server and waits for a connection
        try
        {
            this.merchant2PgServer = new ServerSocket(MERCHANT_TO_GATEWAY_PORT);
            System.out.println("Payment Gateway started");
            System.out.println("\nWaiting for merchant ...");

            //initialize socket and input stream
            this.merchant2PgSocket = this.merchant2PgServer.accept();
            System.out.println("Merchant accepted");

            return true;
        }
        catch(IOException exception)
        {
            exception.printStackTrace();
            return false;
        }
    }

    public boolean pg2MerchantHandshake() throws IOException, ClassNotFoundException
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

    public boolean pg2ClientHandshake()
    {
        try
        {
            // payment gateway -> client : payment gateway PubKey
            this.client2PgOutput = new ObjectOutputStream(this.client2PgSocket.getOutputStream());
            client2PgOutput.writeObject(this.asymKeysInfr.getPublicKey());

            // client -> payment gateway : clientPubKey
            this.client2PgInput = new ObjectInputStream(this.client2PgSocket.getInputStream());
            this.clientPubKey = (PublicKey) client2PgInput.readObject();

            // client -> payment gateway: {clientSymmetricKey}merchantPubKey
            byte[] encrCustomerSymKey = (byte[]) this.client2PgInput.readObject();
            byte[] decrCustomerSymKey = this.asymKeysInfr.encryptDecryptMessage(encrCustomerSymKey, Cipher.DECRYPT_MODE, null, null);
            this.client2PgSymKeysInfr = new SymKeysInfrastructure(new SecretKeySpec(decrCustomerSymKey, "AES"));

            // payment gateway -> client: {acknowledgement}clientSymmetricKey
            this.client2PgOutput.writeObject(client2PgSymKeysInfr.encryptMessage(ACKNOWLEDGE_CLIENT.getBytes()));
            return true;
        }
        catch (IOException | ClassNotFoundException | InvalidKeyException | NoSuchAlgorithmException |
                NoSuchPaddingException | InvalidAlgorithmParameterException exception)
        {
            exception.printStackTrace();
            return false;
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

    public boolean initClientConnection()
    {
        try
        {
            this.client2PgServer = new ServerSocket(CLIENT_TO_GATEWAY_PORT);
            System.out.println("\nWaiting for client ...");

            //initialize socket and input stream
            this.client2PgSocket = this.client2PgServer.accept();
            System.out.println("Client accepted");

            return true;
        }
        catch(IOException exception)
        {
            exception.printStackTrace();
            return false;
        }
    }

    public static void main(String[] args) throws IOException, ClassNotFoundException
    {
        String address = "127.0.0.1";
        PaymentGateway paymentGateway = new PaymentGateway(address);

        boolean flag = false;
        while(true)
        {
            if(!flag)
            {
                flag = paymentGateway.connect();
            }
        }
    }
}
