package communication;
import crypto.AsymKeysInfrastructure;
import crypto.SymKeysInfrastructure;
import org.jetbrains.annotations.Contract;

import javax.crypto.NoSuchPaddingException;
import java.net.*;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

public class PaymentGateway
{
    private static final int MERCHANT_TO_GATEWAY_PORT = 60000;
    private static final String PRIVATE_KEY_PATH = "\\payment_gateway_keys\\privateKey.key";
    private static final String PUBLIC_KEY_PATH = "\\payment_gateway_keys\\publicKey.pub";
    private AsymKeysInfrastructure aki;
    private SymKeysInfrastructure ski;
    private ServerSocket pgServer;
    private Socket merchantPgSocket;
    private ObjectInputStream merchant2pgInput;
    private ObjectOutputStream merchant2pgOutput;
    private PublicKey merchantPubKey;

    public PaymentGateway(String address)
    {
        if(!(initMerchantConnection()))
        {
            throw new ExceptionInInitializerError("Error while initializing connection!");
        }

        this.aki = new AsymKeysInfrastructure();
        if (!this.aki.loadRSAKeys(PUBLIC_KEY_PATH, PRIVATE_KEY_PATH))
        {
            this.aki.initRSAKeyPairs();
            this.aki.saveKeys(PUBLIC_KEY_PATH, PRIVATE_KEY_PATH);
        }

        try
        {
            this.ski = new SymKeysInfrastructure(null);
        }
        catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException |
                InvalidAlgorithmParameterException exception)
        {
            exception.printStackTrace();
        }
    }

    private boolean initMerchantConnection()
    {
        // starts server and waits for a connection
        try
        {
            this.pgServer = new ServerSocket(MERCHANT_TO_GATEWAY_PORT);
            System.out.println("Payment Gateway started");
            System.out.println("Waiting for merchant ...");

            //initialize socket and input stream
            this.merchantPgSocket = this.pgServer.accept();
            System.out.println("Merchant accepted");

            return true;
        }
        catch(IOException exception)
        {
            exception.printStackTrace();
            return false;
        }
    }

    public static void main(String[] args)
    {
        String address = "127.0.0.1";
        PaymentGateway paymentGateway = new PaymentGateway(address);
    }
}
