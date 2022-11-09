package com.signature.AES._AES_GCM_NoPadding;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;


/*
 Possible KEY_SIZE values are 128, 192 and 256
  Possible T_LEN values are 128, 120, 112, 104 and 96
 */
@Slf4j
public class _AES_GCM_NoPadding {

    private SecretKey secretKey;
    private final static int keySize = 128;
    private final static int T_LEN = 128;

    private Cipher cipherEncrypt;

    public void init(){

        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(keySize);
            secretKey = keyGenerator.generateKey();

        }catch (Exception e){
            e.printStackTrace();
        }

    }
    public String encryptMessage(String message){

        try {

        byte[] messageToBytes = message.getBytes();
            cipherEncrypt = Cipher.getInstance("AES/GCM/NOPADDING");
            cipherEncrypt.init(Cipher.ENCRYPT_MODE,secretKey);
         byte[] encryptedByteMessage = cipherEncrypt.doFinal(messageToBytes);
           String encryptedMessage = Base64.getEncoder().encodeToString(encryptedByteMessage);
           return encryptedMessage;

        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }
    public String decryptMessage(String message){
        try {
            byte[] messageToBytes = Base64.getDecoder().decode(message);
            Cipher cipher = Cipher.getInstance("AES/GCM/NOPADDING");
            GCMParameterSpec spec = new GCMParameterSpec(T_LEN,cipherEncrypt.getIV());
            cipher.init(Cipher.DECRYPT_MODE,secretKey,spec);
            byte[] decryptedByteMessage = cipher.doFinal(messageToBytes);
            return new String(decryptedByteMessage);

        }catch (Exception e){
            e.printStackTrace();
        }

        return null;
    }

    public static void main(String[] args) {

        _AES_GCM_NoPadding aes = new _AES_GCM_NoPadding();
        aes.init();
        String encryptMessage = aes.encryptMessage("hello conred");
        log.info("Encrypted Message: {}",encryptMessage);

        String decryptedMessage = aes.decryptMessage(encryptMessage);
        log.info("Decrypted Message: {}",decryptedMessage);


    }
}
