package utils;

import org.jetbrains.annotations.NotNull;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.*;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.ThreadLocalRandom;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Utils
{
private static final String DATE_FORMAT = "dd/MM/yyyy";
private static final String CARD_REGEX = "^(?:4[0-9]{12}(?:[0-9]{3})?|[25][1-7][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]" +
        "{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\\d{3})\\d{11})$";
private static final String PIN_REGEX = "^[0-9]{4}$";

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

public static boolean checkSignature(byte[] encrSignature, PublicKey publicKey, byte[] decrToCompare) throws NoSuchPaddingException,
        NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException
{
    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.DECRYPT_MODE, publicKey);
    byte[] decryptedMessageHash = cipher.doFinal(encrSignature);
    byte[] hash = MessageDigest.getInstance("SHA-256").digest(decrToCompare);
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

public static boolean checkCard(String cardNumber, String expDate, String pin)
{
    LocalDate expirationDate = LocalDate.parse(expDate, DateTimeFormatter.ofPattern(DATE_FORMAT));
    LocalDate today = LocalDate.now(ZoneId.systemDefault());
    Pattern pattern = Pattern.compile(CARD_REGEX);
    Matcher matcher = pattern.matcher(cardNumber);
    if (!matcher.find())
    {
        System.out.println("Incorrect card number!");
        return false;
    }

    if (!checkLuhn(cardNumber))
    {
        System.out.println("Incorrect card number!");
        return false;
    }

    if (expirationDate.isBefore(today))
    {
        System.out.println("Card is expired!");
        return false;
    }

    pattern = Pattern.compile(PIN_REGEX);
    matcher = pattern.matcher(pin);
    if (!matcher.find())
    {
        System.out.println("Incorrect PIN!");
        return false;
    }
    return true;
}

@NotNull
public static byte[] deserializeItem(byte[] text, int offset)
{
    ByteBuffer byteBuffer = ByteBuffer.allocate(Integer.BYTES);
    byteBuffer.put(text, offset, Integer.BYTES);
    int itemLength = bytesToInt(byteBuffer.array());
    offset += Integer.BYTES;

    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
    byteArrayOutputStream.write(text, offset, itemLength);
    return byteArrayOutputStream.toByteArray();
}
}
