package com.signature.RSA.RSA_ECB_PKCS1Padding.SERVER_RSA_ECB_PKCS1Padding;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
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
@Service
public class PUBLIC_KEY_RSA_ECB_PKCS1Padding {
    private PublicKey publicKey;
    private final static String PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAi5C8o8lZ+00KmWrJ0Wyq7BHL7UpNCmkcHMnV6ZzfitseKAG5Okv46qwE2L4spFKx0VLQKRFIYdb0kBEVcPsBZv6LCrTi+VVBQvF0v81gghmGZqj+BVgcuitjASnATNvP8HlR6ISFu2Cpy2KUx/d4bTVAXOEjx/RCU0EfuEGj9f2d01uGBPD0Pwz/jcAdi+qf3FgYfjLmQ+nc0RyR9mcF8S7wXwQGtI3265F+pBoPaq9zSu7Nen4USvhRphlvSuXmrEDkO7MA4JN9b7L4fx34bL+PFU+K2AwV2XaG5hf6WergiW2Pq+6m1IIz0r7oRQo3pQ1kRkSTSqqmhi0BzyX4owIDAQAB";

    public void init() {

        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            publicKey = keyPair.getPublic();
//            log.info("\nPublic Key {}",Base64.getEncoder().encodeToString(publicKey.getEncoded()));
//            log.info("\nPrivate Key {}",Base64.getEncoder().encodeToString(privateKey.getEncoded()));

        } catch (Exception e) {
            e.printStackTrace();
        }
        keyPairGenerator.initialize(1024);
    }
    public void initFromString(){
        try {
            X509EncodedKeySpec keySpecPublicKey = new X509EncodedKeySpec(Base64.getDecoder().decode(PUBLIC_KEY));

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            publicKey = keyFactory.generatePublic(keySpecPublicKey);

        }catch (Exception e){
            e.printStackTrace();
        }
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

}
