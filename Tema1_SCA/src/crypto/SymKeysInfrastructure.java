package crypto;

import org.jetbrains.annotations.Nullable;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Objects;

public class SymKeysInfrastructure
{
    private Cipher cipher;
    private SecretKey secretKey;
    private byte[] iv;

    public SymKeysInfrastructure() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidAlgorithmParameterException {createKey(null);}

    public SymKeysInfrastructure(SecretKey secretKey) throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidAlgorithmParameterException {createKey(secretKey);}

    public boolean createKey(@Nullable SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, InvalidAlgorithmParameterException
    {
        SecureRandom secureRandom = new SecureRandom();
        byte[] keyBytes = new byte[16];
        secureRandom.nextBytes(keyBytes);
        this.secretKey = Objects.requireNonNullElseGet(key, () -> new SecretKeySpec(keyBytes, "AES"));
        this.iv = new byte[12];
        secureRandom.nextBytes(iv);

        this.cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, this.iv); //128 bit auth tag length
        this.cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
        return true;
    }

    public Cipher getCipher()
    {
        return cipher;
    }

    public void setCipher(Cipher cipher)
    {
        this.cipher = cipher;
    }

    public SecretKey getSecretKey()
    {
        return this.secretKey;
    }

    public byte[] encryptMessage(byte[] plainText)
    {
        try
        {
            SecureRandom secureRandom = new SecureRandom();
            this.iv = new byte[12]; //NEVER REUSE THIS IV WITH SAME KEY
            secureRandom.nextBytes(iv);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, this.iv); //128 bit auth tag length
            this.cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

            byte[] cipherText = this.cipher.doFinal(plainText);
            ByteBuffer byteBuffer = ByteBuffer.allocate(4 + this.iv.length + cipherText.length);
            byteBuffer.putInt(this.iv.length);
            byteBuffer.put(this.iv);
            byteBuffer.put(cipherText);
            return byteBuffer.array();
        }
        catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException exception)
        {
            exception.printStackTrace();
            return null;
        }
    }

    public byte[] decryptMessage(byte[] encryptedText)
    {
        try
        {
            ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedText);
            int ivLength = byteBuffer.getInt();
            if (ivLength < 12 || ivLength >= 16)
            {
                throw new IllegalArgumentException("invalid iv length");
            }
            byte[] iv = new byte[ivLength];
            byteBuffer.get(iv);
            byte[] cipherText = new byte[byteBuffer.remaining()];
            byteBuffer.get(cipherText);

            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(this.secretKey.getEncoded(), "AES"), new GCMParameterSpec(128, iv));
            return cipher.doFinal(cipherText);
        }
        catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException exception)
        {
            exception.printStackTrace();
            return null;
        }
    }
}
