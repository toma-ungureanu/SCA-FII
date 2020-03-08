package crypto;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class AsymKeysInfrastructure
{
protected static final String KEYS_LOCATION = "C:\\Users\\Tomy\\IdeaProjects\\Tema1_SCA\\src\\keys";
private PublicKey publicKey;
private PrivateKey privateKey;

public byte[] encryptDecryptMessage(@NotNull byte[] message, int encryptDecrypt, @Nullable PublicKey publicKey,
                                    @Nullable PrivateKey privateKey)
{
    try
    {
        Cipher cipher = Cipher.getInstance("RSA");
        if(encryptDecrypt == Cipher.ENCRYPT_MODE)
        {
            if(publicKey != null)
            {
                cipher.init(encryptDecrypt, publicKey);
            }
            else
            {
                cipher.init(encryptDecrypt, this.publicKey);
            }
        }
        else
        {
            if(privateKey != null)
            {
                cipher.init(encryptDecrypt, privateKey);
            }
            else
            {
                cipher.init(encryptDecrypt, this.privateKey);
            }
        }
        return cipher.doFinal(message);
    }
    catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException exception)
    {
        exception.printStackTrace();
        return null;
    }
}

public PublicKey getPublicKey()
{
    return publicKey;
}

public PrivateKey getPrivateKey()
{
    return privateKey;
}

/**
 * Function used to initialize the private and public keys
 */
public void initRSAKeyPairs()
{
    try
    {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(4096);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.publicKey = keyPair.getPublic();
        this.privateKey = keyPair.getPrivate();
        System.out.println("Public key format: " + this.publicKey.getFormat());
        System.out.println("Private key format: " + this.privateKey.getFormat());
    }
    catch (NoSuchAlgorithmException exception)
    {
        exception.printStackTrace();
    }
}

/**
 * Method used to load the private/public key-pair from file
 * @return true if the keys were loaded successfully, false otherwise
 */
public boolean loadRSAKeys(String pubKeyLocation, String privKeyLocation)
{
    try
    {
        Path path = Paths.get(KEYS_LOCATION + privKeyLocation);
        byte[] bytes = Files.readAllBytes(path);
        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        this.privateKey = kf.generatePrivate(ks);

        path = Paths.get(KEYS_LOCATION + pubKeyLocation);
        bytes = Files.readAllBytes(path);
        X509EncodedKeySpec x509ks = new X509EncodedKeySpec(bytes);
        this.publicKey = kf.generatePublic(x509ks);
        System.out.println("Keys loaded!");
        return true;
    }
    catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException exception)
    {
        exception.printStackTrace();
        return false;
    }
}

public void saveKeys(String pubKeyLocation, String privKeyLocation)
{
    try
    {
        FileOutputStream out = new FileOutputStream(KEYS_LOCATION + pubKeyLocation);
        out.write(this.publicKey.getEncoded());
        out.close();

        out = new FileOutputStream(KEYS_LOCATION + privKeyLocation);
        out.write(this.privateKey.getEncoded());
        out.close();
        System.out.println("Keys saved!");
    }
    catch (IOException exception)
    {
        exception.printStackTrace();
    }
}
}
