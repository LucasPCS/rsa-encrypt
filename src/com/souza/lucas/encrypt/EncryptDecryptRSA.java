package com.souza.lucas.encrypt;

import javax.crypto.Cipher;
import java.io.*;
import java.security.*;
import java.util.Base64;

public class EncryptDecryptRSA {
    public static final String ALGORITHM = "RSA";
    public static final Integer KEY_SIZE = 2048;

    public static void main(String[] args) {
        try {
            System.out.println("Gerando pares de chaves");
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
            SecureRandom secureRandom = new SecureRandom();

            keyPairGenerator.initialize(KEY_SIZE, secureRandom);
            KeyPair pair = keyPairGenerator.generateKeyPair();

            PublicKey publicKey = pair.getPublic();
            PrivateKey privateKey = pair.getPrivate();

            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

            String message = reader.readLine();

            byte[] encryptedMessage = encrypt(message, publicKey);
            String encryptionBase64 = Base64.getEncoder().encodeToString(encryptedMessage);
            System.out.println("Mensagem encriptada = " + encryptionBase64);

            String decryptedMessage = decrypt(encryptedMessage, privateKey);
            System.out.println("Mensagem decriptada =  " + decryptedMessage);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static byte[] encrypt(String message, PublicKey publicKey) {
        byte[] cipherText = null;

        try {
            final Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            cipherText = cipher.doFinal(message.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }

        return cipherText;
    }

    public static String decrypt(byte[] message, PrivateKey privateKey) {
        byte[] decryptedText = null;

        try {
            final Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            decryptedText = cipher.doFinal(message);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return new String(decryptedText);
    }


}
