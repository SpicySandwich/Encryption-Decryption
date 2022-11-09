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
public class SERVER_DECRYPT_DES_CBC_PKCS5Padding {

    private SecretKey secretKey;

    private Cipher decryptCipher;

    private static final String IV_STRING_ENCODED = "2wShzBInAVE=";
    private static final String SECRET_KEY_STRING_ENCODED = "YUbf/lHq4Oo=";

    public SERVER_DECRYPT_DES_CBC_PKCS5Padding() throws Exception {
        this.secretKey = generateKey();
        cypherInit();
    }

    public static SecretKey generateKey() throws Exception {
       return new SecretKeySpec(Base64.getDecoder().decode(SECRET_KEY_STRING_ENCODED),"DES");
    }

    public void cypherInit() throws Exception{
        decryptCipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        decryptCipher.init(Cipher.DECRYPT_MODE,secretKey, new IvParameterSpec(Base64.getDecoder().decode(IV_STRING_ENCODED)));
    }

    public String decryption(byte[] message) throws  Exception{
        return new String(decryptCipher.doFinal(message));
    }

    public static void main(String[] args) throws Exception {
        SERVER_DECRYPT_DES_CBC_PKCS5Padding sv = new SERVER_DECRYPT_DES_CBC_PKCS5Padding();
        String encryptedMessage = "WwLU5SfaPNTzBmosnte5Og==";
        String decryptedMessage = sv.decryption(Base64.getDecoder().decode(encryptedMessage));
        log.info("\nDecrypted Message: {}",decryptedMessage);

    }

}

