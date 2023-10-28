package org.example.exercicio7;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.security.*;
import java.util.Arrays;

public class CipherControl {

    static class CipherTextAuth {
        byte[] cipherText;
        byte[] authText;

        public CipherTextAuth(byte[] cipherText, byte[] authText) {
            this.cipherText = cipherText;
            this.authText = authText;
        }

        public static String buildString(byte[] bytes) {
            StringBuilder builder = new StringBuilder();
            for (byte b: bytes) {
                builder.append(String.format("%02x", b));
            }
            return builder.toString();
        }

        @Override
        public String toString() {
            String cipher = buildString(this.cipherText);
            String auth = buildString(this.authText);
            return cipher + " -> " + auth;
        }
    }

    public static CipherTextAuth cipher(byte[] message, String additional, SecretKey key, byte[] iv, int authLength) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, ShortBufferException {
        GCMParameterSpec parameterSpec = new GCMParameterSpec(authLength, iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

        cipher.updateAAD(additional.getBytes());
         byte[] bytes = new byte[cipher.getOutputSize(message.length)];

        cipher.doFinal(message, 0, message.length, bytes);
        byte[] auth = Arrays.copyOfRange(bytes, bytes.length - (authLength / Byte.SIZE), bytes.length);

        return new CipherTextAuth(bytes, auth);
    }

    public static byte[] decipher(byte[] cipherText, byte[] additional, Key key, byte[] iv, int authLength) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        GCMParameterSpec parameterSpec = new GCMParameterSpec(authLength, iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

        cipher.updateAAD(additional);
        return cipher.doFinal(cipherText);
    }

    private static void printString(byte[] bytes) {
        for (byte b: bytes) {
            System.out.print((char) b);
        }
        System.out.println();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, ShortBufferException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        SecureRandom secRandom = new SecureRandom();
        keyGen.init(secRandom);
        SecretKey key = keyGen.generateKey();

        CipherTextAuth bytes = cipher("Hello I am Miguel".getBytes(), "123", key, "123456789876".getBytes(), 128);
        byte[] bytes2 = decipher(bytes.cipherText, "123".getBytes(), key, "123456789876".getBytes(), 128);
        printString(bytes2);
    }
}
