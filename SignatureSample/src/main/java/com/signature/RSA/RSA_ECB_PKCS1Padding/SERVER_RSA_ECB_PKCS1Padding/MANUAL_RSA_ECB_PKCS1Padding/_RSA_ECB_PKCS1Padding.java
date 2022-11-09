package com.signature.RSA.RSA_ECB_PKCS1Padding.SERVER_RSA_ECB_PKCS1Padding.MANUAL_RSA_ECB_PKCS1Padding;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

/*
        AES/CBC/NoPadding (128)
        AES/CBC/PKCS5Padding (128)
        AES/ECB/NoPadding (128)
        AES/ECB/PKCS5Padding (128)
        RSA/ECB/PKCS1Padding (1024, 2048)
        RSA/ECB/OAEPWithSHA-1AndMGF1Padding (1024, 2048)

 */

@Data
@Slf4j
public class _RSA_ECB_PKCS1Padding {

    private PublicKey publicKey;
    private PrivateKey privateKey;

    public _RSA_ECB_PKCS1Padding() {

        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();

        } catch (Exception e) {
            e.printStackTrace();
        }
        keyPairGenerator.initialize(1024);
    }

    public String encrypt(String message) {
        try {
            byte[] messageToBytes = message.getBytes();
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE,publicKey);
            byte[] encryptedMessage = cipher.doFinal(messageToBytes);
            return Base64.getEncoder().encodeToString(encryptedMessage);

        }catch (Exception e){
            throw new RuntimeException(e.getMessage());
        }

    }
    public String decrypt(String message){
        try {
            byte[] decodedMessage = Base64.getDecoder().decode(message);
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE,privateKey);
            byte[] decryptedMessage = cipher.doFinal(decodedMessage);
            return new String(decryptedMessage, StandardCharsets.UTF_8);

        }catch (Exception e){
          throw new RuntimeException(e.getMessage());
        }

    }

    public static void main(String[] args) {

        _RSA_ECB_PKCS1Padding rsa = new _RSA_ECB_PKCS1Padding();
      String encryptedMessage =  rsa.encrypt("Hello Conred");
        log.info("\nEncrypted message: {}",encryptedMessage);

        String decryptedMessage = rsa.decrypt(encryptedMessage);
        log.info("\nDecrypted message: {}",decryptedMessage);

    }


}
