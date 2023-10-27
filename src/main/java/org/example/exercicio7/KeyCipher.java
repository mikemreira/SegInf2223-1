package org.example.exercicio7;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Enumeration;
import java.util.Scanner;


/**
 * Ler chaves assimétricas dos .pfx e cifrar a chave simétrica que vamos receber
 * Configurar um certpathvalidator, encriptar com a chave publica nos ficheiros .cer e decriptar com a privada do .pfx
 * Validar os trust anchors na cadeia de certificaçao
 */

public class KeyCipher {
    public static byte[] cipherKey(PublicKey key, SecretKey keyToCipher) throws NoSuchAlgorithmException, NoSuchPaddingException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, InvalidKeySpecException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA1ANDMGF1PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(keyToCipher.getEncoded());
    }

    public static Key decipherKey(byte[] key, String fileName) throws NoSuchPaddingException, NoSuchAlgorithmException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        byte[] bytes;
        keyStore.load(
                new FileInputStream(fileName),
                "changeit".toCharArray()
        );
        Enumeration<String> entries = keyStore.aliases();
        do {
            String alias = entries.nextElement();
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, "changeit".toCharArray());
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            bytes = cipher.doFinal(key);
            return new SecretKeySpec(bytes, "AES");
        } while (entries.hasMoreElements());
    }

    public static void printString(byte[] bytes) {
        for (byte b: bytes) {
            System.out.print((char) b);
        }
        System.out.println();
    }

    public static String buildString(byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        for (byte b : bytes) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, UnrecoverableKeyException, NoSuchPaddingException, CertificateException, KeyStoreException, IOException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, CertPathValidatorException, InvalidAlgorithmParameterException, InvalidKeySpecException, ShortBufferException {
        String[] intermediates = {"./certificates-keys/intermediates/CA1-int.cer", "./certificates-keys/intermediates/CA2-int.cer"};
        String[] trustAnchors = {"./certificates-keys/trust-anchors/CA1.cer", "./certificates-keys/trust-anchors/CA2.cer"};

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        SecureRandom secRandom = new SecureRandom();
        keyGen.init(secRandom);
        SecretKey publicKey = keyGen.generateKey();

        byte[] keyBytes = new byte[] {};
        byte[] text = new byte[] {};

        for (;;) {

            System.out.print("$ ");
            Scanner key = new Scanner(System.in);
            String[] str = key.nextLine().split(" ");
            switch (str[0].concat(" " + str[1])) {
                case "jwe enc" -> {
                    if (str.length != 4) {
                        System.out.println("Expected 4 arguments, but received " + str.length);
                        break;
                    }
                    text = CipherControl.cipher(str[2].getBytes(),"123", publicKey, "123456789".getBytes(), 128);
                    keyBytes = cipherKey(CertificateValidator.validateCertPath(str[3], intermediates, trustAnchors), publicKey);
                    System.out.print("JWE token = ");
                    printString(text);
                }
                case "jwe dec" -> {
                    if (str.length != 4) {
                        System.out.println("Expected 4 arguments, but input was " + str.length);
                        break;
                    }
                    Key keyDecipher = decipherKey(keyBytes, "./certificates-keys/pfx/" + str[3]);
                    byte[] decipherText = CipherControl.decipher(str[2].getBytes(), "123", keyDecipher, "123456789".getBytes(), 128);
                    System.out.print("Decrypted text = ");
                    printString(decipherText);
                }
                case "quit" -> {
                    return;
                }
            }
        }
    }
}
