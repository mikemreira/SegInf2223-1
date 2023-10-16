package org.example.exercicio7;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.security.*;
import java.util.Arrays;
import java.util.Map;

public class CipherControl {
    public static byte[] cipher(String message, String additional, SecretKey key, byte[] iv, int authLength) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, ShortBufferException {
        GCMParameterSpec parameterSpec = new GCMParameterSpec(authLength, iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

        cipher.updateAAD(additional.getBytes());
        byte[] bytes = new byte[cipher.getOutputSize(message.length())];
        cipher.doFinal(message.getBytes(), 0, message.length(), bytes);

        byte[] auth = Arrays.copyOfRange(bytes, bytes.length - (authLength / Byte.SIZE), bytes.length);
        byte[] cipherText = Arrays.copyOfRange(bytes, 0, bytes.length - (authLength / Byte.SIZE));
        System.out.print("Cipher text: ");
        prettyPrint(cipherText);
        System.out.print("Auth: ");
        prettyPrint(auth);
        prettyPrint(bytes);
        return bytes;
    }

    public static byte[] decipher(byte[] cipherText, String additional, SecretKey key, byte[] iv, int authLength) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        GCMParameterSpec parameterSpec = new GCMParameterSpec(authLength, iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

        cipher.updateAAD(additional.getBytes());
        byte[] bytes = cipher.doFinal(cipherText);
        prettyPrint(bytes);
        return bytes;
    }

    private static void prettyPrint(byte[] tag) {
        for (byte b: tag) {
            System.out.printf("%02x", b);
        }
        System.out.println();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        SecureRandom secRandom = new SecureRandom();
        keyGen.init(secRandom);
        SecretKey key = keyGen.generateKey();

        byte[] bytes = cipher("Hello I am Miguel", "123", key, "12345678987654321".getBytes(), 128);
        byte[] bytes2 = decipher(bytes, "123", key, "12345678987654321".getBytes(), 128);
    }
}
