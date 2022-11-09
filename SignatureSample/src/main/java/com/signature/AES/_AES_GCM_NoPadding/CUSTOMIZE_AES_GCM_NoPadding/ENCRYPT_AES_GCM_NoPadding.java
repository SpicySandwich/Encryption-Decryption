package com.signature.AES._AES_GCM_NoPadding.CUSTOMIZE_AES_GCM_NoPadding;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

/*
 Possible KEY_SIZE values are 128, 192 and 256
  Possible T_LEN values are 128, 120, 112, 104 and 96
 */

@Slf4j
public class ENCRYPT_AES_GCM_NoPadding {

    private static SecretKey secretKey;
    private final static int keySize = 128;
    private final static int T_LEN = 128;

    private  byte[] IV;

    public void initFromString(){

        String secretKey1 = "j6g35n6x8ziACCoQ0PhEnw==";
        String IVs = "GUY9r7N7VNipFeVd";

        try {
            byte[] secretKeyDecode = Base64.getDecoder().decode(secretKey1);
            secretKey = new SecretKeySpec(secretKeyDecode,"AES");
            this.IV = Base64.getDecoder().decode(IVs);

        }catch (Exception e){
            e.printStackTrace();
        }

    }

    public String encryptMessage(String message){

        try {
            byte[] messageToBytes = message.getBytes();
            Cipher cipher = Cipher.getInstance("AES/GCM/NOPADDING");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(T_LEN,IV);
            cipher.init(Cipher.ENCRYPT_MODE,secretKey,gcmParameterSpec);
            byte[] encryptedByteMessage = cipher.doFinal(messageToBytes);

            String encryptedMessage = Base64.getEncoder().encodeToString(encryptedByteMessage);
            return encryptedMessage;

        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    //generete a key
    private void getKeys(){
//        log.info("\nSecret key: {}",Base64.getEncoder().encodeToString(secretKey.getEncoded()));
        log.info("\nIV key: {}",Base64.getEncoder().encodeToString(IV));
    }

    public static void main(String[] args) {
        ENCRYPT_AES_GCM_NoPadding aes = new ENCRYPT_AES_GCM_NoPadding();
        aes.initFromString();
        String encryptMessage = aes.encryptMessage("hello conred");
        log.info("\nEncrypted Message: {}",encryptMessage);

        aes.getKeys(); //generete a key
    }
}
