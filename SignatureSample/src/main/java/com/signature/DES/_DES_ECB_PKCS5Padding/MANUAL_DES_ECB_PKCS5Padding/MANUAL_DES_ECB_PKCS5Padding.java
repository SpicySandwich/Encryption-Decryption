package com.signature.DES._DES_ECB_PKCS5Padding.MANUAL_DES_ECB_PKCS5Padding;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.util.Base64;

/*
 DES/CBC/NoPadding (56)
 DES/CBC/PKCS5Padding (56)
 DES/ECB/NoPadding (56)
 DES/ECB/PKCS5Padding (56)
 */

//ECB don't need IV
@Slf4j
public class MANUAL_DES_ECB_PKCS5Padding {
    private SecretKey secretKey;
    private Cipher encryptCipher;
    private Cipher decryptCipher;

    public MANUAL_DES_ECB_PKCS5Padding() throws Exception {
        this.secretKey = generateKey();
        cypherInit();
    }

    public MANUAL_DES_ECB_PKCS5Padding(SecretKey secretKey) throws Exception{
        this.secretKey = secretKey;
        cypherInit();
    }

    public static SecretKey generateKey() throws Exception {
        return KeyGenerator.getInstance("DES").generateKey();
    }

    public void cypherInit() throws Exception{
        encryptCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE,secretKey);

        decryptCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        decryptCipher.init(Cipher.DECRYPT_MODE,secretKey);
    }
    public byte[] encryption(String message) throws  Exception{
        return encryptCipher.doFinal(message.getBytes());
    }
    public String decryption(byte[] message) throws  Exception{
        return new String(decryptCipher.doFinal(message));
    }

    public static void main(String[] args) throws Exception {

        SecretKey secretKey = MANUAL_DES_ECB_PKCS5Padding.generateKey();
        log.info("\nEncoded Key: {}",encode(secretKey.getEncoded()));

        String message = "This is conred";

        MANUAL_DES_ECB_PKCS5Padding des = new MANUAL_DES_ECB_PKCS5Padding(secretKey);

        byte[] encryptedBytes =  des.encryption(message);
        String encryptedMessage = encode(encryptedBytes);
        log.info("\nEncrypted message: {}",encryptedMessage);

        String decryptedMessage = des.decryption(encryptedBytes);
        log.info("\nDecrypted message: {}",decryptedMessage);


    }
    public static String encode(byte[] encodeMessage){
        return Base64.getEncoder().encodeToString(encodeMessage);
    }

    public static byte[] decode(String decodeMessage){
        return  Base64.getDecoder().decode(decodeMessage);
    }

}

