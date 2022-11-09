package com.signature.RSA.RSA_ECB_PKCS1Padding.SERVER_RSA_ECB_PKCS1Padding.MANUAL_RSA_ECB_PKCS1Padding;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
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
public class Customize_RSA_ECB_PKCS1Padding {


    private PublicKey publicKey;
    private PrivateKey privateKey;

    private final static String PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAi5C8o8lZ+00KmWrJ0Wyq7BHL7UpNCmkcHMnV6ZzfitseKAG5Okv46qwE2L4spFKx0VLQKRFIYdb0kBEVcPsBZv6LCrTi+VVBQvF0v81gghmGZqj+BVgcuitjASnATNvP8HlR6ISFu2Cpy2KUx/d4bTVAXOEjx/RCU0EfuEGj9f2d01uGBPD0Pwz/jcAdi+qf3FgYfjLmQ+nc0RyR9mcF8S7wXwQGtI3265F+pBoPaq9zSu7Nen4USvhRphlvSuXmrEDkO7MA4JN9b7L4fx34bL+PFU+K2AwV2XaG5hf6WergiW2Pq+6m1IIz0r7oRQo3pQ1kRkSTSqqmhi0BzyX4owIDAQAB";


    private final static String PRIVATE_KEY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCLkLyjyVn7TQqZasnRbKrsEcvtSk0KaRwcydXpnN+K2x4oAbk6S/jqrATYviykUrHRUtApEUhh1vSQERVw+wFm/osKtOL5VUFC8XS/zWCCGYZmqP4FWBy6K2MBKcBM28/weVHohIW7YKnLYpTH93htNUBc4SPH9EJTQR+4QaP1/Z3TW4YE8PQ/DP+NwB2L6p/cWBh+MuZD6dzRHJH2ZwXxLvBfBAa0jfbrkX6kGg9qr3NK7s16fhRK+FGmGW9K5easQOQ7swDgk31vsvh/Hfhsv48VT4rYDBXZdobmF/pZ6uCJbY+r7qbUgjPSvuhFCjelDWRGRJNKqqaGLQHPJfijAgMBAAECggEAA1devMkYR2TryQp+dG4WlXpDmJW7zHEBxEqsvWANFgTy7uBDr/qbpfqiTxIWfYShTzKdWy5XvkfoKP7PtZm8ydt0Nrhn6rI40sJ3GhRvqA22YwTOuBAI+AgL4b4/JVfp3Yb6CAgML5U722urxjHNh0fMF60oLyRQ5i9b9AxWQZBcuud26djLCgFrFHBdljpCzR8ebiqjKQrkLhGGAVN/zNfik70T/QqjlqCR3kMWzLfPLip9QE4d4RZH0L9huj4F3b1WlMFUG8XjTGQ8TW96hSsUaZnj5iQvq9FPWXe2n2OTFFAUWM/0pCDMEqs8HL4BSxdARuamkZsmUPBY4GumwQKBgQDRT3PlyBqigcX49F8UL1DmFU3T9Vk5USt0zwD8n7TqfhHChvMMvmekHYYELQkCNh0+JxFjAuF+jIZw5+k/cICnd7/SKdhBM9zksRiFCFn3PzGyPyD5CIlHPnBT053h0vqSTa3SdT4Id6O5yLxJTpZSeWW0Q6dYEzRlUUGbIotvYQKBgQCqsomC+yGOJFIbWAq4VkMVFdwqi5ztH3EIE3OD56nttWindeZFz94aeIXEuxygPsA8Ur7/9NwGSrzI6rL2+J79ABiYVhIVJ5MEDx4sDY/2oUz+LHHfoiNjaHKC5PHXaLjBHgcYmgF4/DTBl0H2lYQK2FqdjFWG4a9ftBO7ZJA6gwKBgGSJbFrntdtuyB/fiTfRzmLlwr9Xrua4FU6DC69MKwMjUPaGCYKKho+u2qtw0k3snjk3XMOZI6S8bOsYidG+AR3viASzsrsG5Ug3xFZJ/6SiBwXeCsFzlzTQSfYJxGEvDMpvY1melRBOHydiwwXXKJ8uzmo6wMuuVdGAqSmR+zWhAoGANdBFY+KyKHKw4+f0sTqYuWwD1fHfzi2sX8RqFXqSattXG/wiVX374lJ+sY/frXE6/4mCp4TVXLJxI9JCC3REAzTljBkOaFbqlUwC0haQfUtKz5LJb5xZFbzW5Qcyaxubq15BFHNw5Wh1ZVa/N/LZBuZAYwzb5cL+m+hUlC5W/esCgYEAmHJtkfVMv/ktqAvBbp/yoozBgMDPotxrbgHlG9MkTM7A0VvKFEMHJ0+sIy9UjK6yrI35zt+IQuQbk7HmNsa0pH1POjDXqO+A5nKyZzm+7UXWBGTX0CPscmLBoAUCsP4NWMJCmxrdiyx0YDSZnCLb1eBCMoghrDsjxgIQvKiP5KY=";

    public void init() {

        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();
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
            PKCS8EncodedKeySpec keySpecPrivateKey = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(PRIVATE_KEY));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            publicKey = keyFactory.generatePublic(keySpecPublicKey);
            privateKey = keyFactory.generatePrivate(keySpecPrivateKey);
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

        Customize_RSA_ECB_PKCS1Padding rsa = new Customize_RSA_ECB_PKCS1Padding();
        rsa.init();
        rsa.initFromString();
        String encryptedMessage =  rsa.encrypt("Hello Conred");
        log.info("\nEncrypted message: {}",encryptedMessage);

        String decryptedMessage = rsa.decrypt("");
        log.info("\nDecrypted message: {}",decryptedMessage);

    }

}
