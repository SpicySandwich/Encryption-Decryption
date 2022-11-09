package com.signature.AES._AES_CBC_PKCS5Padding.MANUAL_DECRYPT_AES_CBC_PKCS5Padding;

import lombok.extern.slf4j.Slf4j;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileReader;
import java.util.Base64;

@Slf4j
public class DECRYPT_AES_CBC_PKCS5Padding {

    private static final String secretKeyWord = "conred_secretKey";
    private static final String secretKeyEncoded = "Y29ucmVkX3NlY3JldEtleQ==";

    public static void main( String[] args ) throws Exception {


        String myDecryptText = aesDecryption("aqwm39Htohc+0mFDfZzlPKzu0FmHUnMWT/iLOeENmCdKQ3NvAto3vlVIIGiklwIF",secretKeyEncoded, "VT0Ez9+kpWtvVwCLFaDjhQ==");
        log.info("\nDecrypted message: {}",myDecryptText);

    }

    public static String aesDecryption (String cipherText, String myKey,String IV) throws Exception {

        byte[] secretKey= Base64.getDecoder().decode(myKey);
        byte[] IVs = Base64.getDecoder().decode(IV);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(secretKey, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(IVs);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        byte[] decryptedText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(decryptedText);
    }
}
