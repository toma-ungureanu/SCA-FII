package utils;

import org.jetbrains.annotations.NotNull;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.concurrent.ThreadLocalRandom;

public class Utils
{
    public static final int SIZE_OF_LONG = 8;
    public static final int SIZE_OF_DOUBLE = 8;

    @NotNull
    public static byte[] doubleToBytes(double value)
    {
        byte[] bytes = new byte[8];
        ByteBuffer.wrap(bytes).putDouble(value);
        return bytes;
    }

    @NotNull
    public static byte[] longToBytes(long x)
    {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(x);
        return buffer.array();
    }

    @NotNull
    public static byte[] intToBytes(int x)
    {
        ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);
        buffer.putInt(x);
        return buffer.array();
    }

    @NotNull
    public static int bytesToInt(byte[] bytes)
    {
        return ByteBuffer.wrap(bytes).getInt();
    }

    public static double bytesToDouble(byte[] bytes)
    {
        return ByteBuffer.wrap(bytes).getDouble();
    }

    public static long generateNonce()
    {
        ThreadLocalRandom random = ThreadLocalRandom.current();
        return random.nextLong(1_000_000_000L, 10_000_000_000L);
    }

    public static long bytesToLong(byte[] bytes)
    {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.put(bytes);
        buffer.flip();//need flip
        return buffer.getLong();
    }

    public static boolean checkLuhn(@NotNull String cardNo)
    {
        int nDigits = cardNo.length();
        int nSum = 0;
        boolean isSecond = false;
        for (int i = nDigits - 1; i >= 0; i--)
        {
            int d = cardNo.charAt(i) - '0';
            if (isSecond)
            {
                d *= 2;
            }
            nSum += d / 10;
            nSum += d % 10;
            isSecond = !isSecond;
        }
        return (nSum % 10 == 0);
    }

    public static byte[] generateSignature(@NotNull byte[] buffer, PrivateKey privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException
    {
        // create the hash containing the session id
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(MessageDigest.getInstance("SHA-256").digest(buffer));
    }

    public static boolean checkSignature(byte[] encrSignature, PublicKey publicKey, byte[] toCompare) throws NoSuchPaddingException,
            NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException
    {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] decryptedMessageHash = cipher.doFinal(encrSignature);
        byte[] hash = MessageDigest.getInstance("SHA-256").digest(toCompare);
        if (decryptedMessageHash.length != hash.length)
        {
            return false;
        }

        for (int i = 0; i < decryptedMessageHash.length; i++)
        {
            if (decryptedMessageHash[i] != hash[i])
            {
                return false;
            }
        }
        return true;
    }
}
