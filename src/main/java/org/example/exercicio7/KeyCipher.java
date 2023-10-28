package org.example.exercicio7;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;
import java.util.Scanner;


/**
 * Ler chaves assimétricas dos .pfx e cifrar a chave simétrica que vamos receber
 * Configurar um certpathvalidator, encriptar com a chave publica nos ficheiros .cer e decriptar com a privada do .pfx
 * Validar os trust anchors na cadeia de certificaçao
 */

public class KeyCipher {
    public static byte[] cipherKey(PublicKey key, SecretKey keyToCipher) throws NoSuchAlgorithmException, NoSuchPaddingException, KeyStoreException, IOException, CertificateException, UnrecoverableKeyException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, InvalidKeySpecException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
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
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
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
        CipherControl.CipherTextAuth text;

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
                    String JOSE_HEADER = "{\"alg\":\"RSA-OAEP\",\"enc\":\"A256GCM\"}";
                    String JOSE_HEADER_BASE64 = Base64.getUrlEncoder().withoutPadding().encodeToString(JOSE_HEADER.getBytes());
                    text = CipherControl.cipher(str[2].getBytes(),"123", publicKey, "123456789".getBytes(), 128);
                    keyBytes = cipherKey(CertificateValidator.validateCertPath(str[3], intermediates, trustAnchors), publicKey);
                    String JWE_KEY_BASE64 = Base64.getUrlEncoder().withoutPadding().encodeToString(keyBytes);
                    String IV_BASE64 = Base64.getUrlEncoder().withoutPadding().encodeToString("123456789".getBytes());
                    String AAD_BASE64 = Base64.getUrlEncoder().withoutPadding().encodeToString("123".getBytes());
                    String CIPHER_TEXT_BASE64 = Base64.getUrlEncoder().withoutPadding().encodeToString(text.cipherText);
                    String CIPHER_AUTH_BASE64 = Base64.getUrlEncoder().withoutPadding().encodeToString(text.authText);
                    System.out.print("JWE token = ");
                    String JWE_TOKEN = JOSE_HEADER_BASE64 + "." + JWE_KEY_BASE64 + "." + IV_BASE64 + "." + CIPHER_TEXT_BASE64 + "." + CIPHER_AUTH_BASE64;
                    System.out.println(JWE_TOKEN);
                }
                case "jwe dec" -> {
                    if (str.length != 4) {
                        System.out.println("Expected 4 arguments, but input was " + str.length);
                        break;
                    }
                    String[] JWE_SPLIT = str[2].split("\\.");
                    for (String str1 : JWE_SPLIT) {
                        System.out.println(str1);
                    }
                    byte[] JOSE_HEADER = Base64.getUrlDecoder().decode(JWE_SPLIT[0]);
                    byte[] CIPHER_DECODE = Base64.getUrlDecoder().decode(JWE_SPLIT[3]);
                    printString(CIPHER_DECODE);
                    byte[] IV = Base64.getUrlDecoder().decode(JWE_SPLIT[2]);
                    printString(IV);
                    byte[] KEY = Base64.getUrlDecoder().decode(JWE_SPLIT[1]);
                    Key keyDecipher = decipherKey(KEY, "./certificates-keys/pfx/" + str[3]);
                    byte[] AAD = Base64.getUrlDecoder().decode(JWE_SPLIT[4]);
                    printString(AAD);
                    byte[] decipherText = CipherControl.decipher(CIPHER_DECODE, buildString(AAD), keyDecipher, IV, 128);
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
