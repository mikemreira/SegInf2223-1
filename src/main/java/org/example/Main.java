package org.example;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class Main {
    public static void main(String[] args) {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            SecureRandom secRandom = new SecureRandom();
            keyGen.init(secRandom);
            SecretKey key = keyGen.generateKey();

            Cipher cipher = Cipher.getInstance("AES/GCM/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            cipher.doFinal(args[0].getBytes());
        } catch(Exception e) {}
    }
}
