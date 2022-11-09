package com.signature.DES._DES_CBC_PKCS5Paddin.SERVER_DES_CBC_PKCS5Padding;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

/*
 DES/CBC/NoPadding (56)
 DES/CBC/PKCS5Padding (56)
 DES/ECB/NoPadding (56)
 DES/ECB/PKCS5Padding (56)
 */
@Slf4j
public class SERVER_ENCRYPT_DES_CBC_PKCS5Padding {

    private SecretKey secretKey;
    private Cipher encryptCipher;

    private static final String IV_STRING_ENCODED = "2wShzBInAVE=";
    private static final String SECRET_KEY_STRING_ENCODED = "YUbf/lHq4Oo=";

    public SERVER_ENCRYPT_DES_CBC_PKCS5Padding() throws Exception {
        this.secretKey = generateKey();
        cypherInit();
    }

    public static SecretKey generateKey() throws Exception {
        return new SecretKeySpec(Base64.getDecoder().decode(SECRET_KEY_STRING_ENCODED),"DES");
    }

    public void cypherInit() throws Exception{
        encryptCipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        encryptCipher.init(Cipher.ENCRYPT_MODE,secretKey, new IvParameterSpec(Base64.getDecoder().decode(IV_STRING_ENCODED)));
//         byte[] IV = encryptCipher.getIV();
//         log.info("IV parameters value {}",Base64.getEncoder().encodeToString(IV));

    }
    public byte[] encryption(String message) throws  Exception{
        return encryptCipher.doFinal(message.getBytes());
    }

    public static void main(String[] args)throws Exception  {

        String message = "This is conred";
        SERVER_ENCRYPT_DES_CBC_PKCS5Padding des = new SERVER_ENCRYPT_DES_CBC_PKCS5Padding();

        byte[] encryptedBytes =  des.encryption(message);
        String encryptedMessage = Base64.getEncoder().encodeToString(encryptedBytes);
        log.info("\nEncrypted message: {}",encryptedMessage);

//        SecretKey secretKey = SERVER_ENCRYPT_DES_CBC_PKCS5Padding.generateKey();

//        log.info("\nEncoded Key: {}",Base64.getEncoder().encodeToString(secretKey.getEncoded()));


    }


}