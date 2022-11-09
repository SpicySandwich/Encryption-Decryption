package com.signature.AES._AES_GCM_NoPadding.CUSTOMIZE_AES_GCM_NoPadding;

import com.signature.AES._AES_GCM_NoPadding._AES_GCM_NoPadding;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

/*
 Possible KEY_SIZE values are 128, 192 and 256
  Possible T_LEN values are 128, 120, 112, 104 and 96
 */

@Slf4j
public class DECRYPT_AES_GCM_NoPadding {


    private static SecretKey secretKey;
    private final static int keySize = 128;
    private final static int T_LEN = 128;
    private  byte[] IV;

    public void initFromString(String IV){

        String secretKey1 = "j6g35n6x8ziACCoQ0PhEnw==";

        try {
        byte[] secretKeyDecode = Base64.getDecoder().decode(secretKey1);
        secretKey = new SecretKeySpec(secretKeyDecode,"AES");
        this.IV = Base64.getDecoder().decode(IV);

        }catch (Exception e){
            e.printStackTrace();
        }

    }

    public String decryptMessage(String message){
        try {
            byte[] messageToBytes = Base64.getDecoder().decode(message);
            Cipher cipher = Cipher.getInstance("AES/GCM/NOPADDING");
            GCMParameterSpec spec = new GCMParameterSpec(T_LEN,IV);
            cipher.init(Cipher.DECRYPT_MODE,secretKey,spec);
            byte[] decryptedByteMessage = cipher.doFinal(messageToBytes);
            return new String(decryptedByteMessage);

        }catch (Exception e){
            e.printStackTrace();
        }

        return null;
    }

    //generete a key
//    private void getKeys(){
//        log.info("\nSecret key: {}",Base64.getEncoder().encodeToString(secretKey.getEncoded()));
//        log.info("\nIV key: {}",Base64.getEncoder().encodeToString(IV));
//    }

    public static void main(String[] args) {

        DECRYPT_AES_GCM_NoPadding aes = new DECRYPT_AES_GCM_NoPadding();
        aes.initFromString("GUY9r7N7VNipFeVd");

        String encryptMessage = "jj0qGxOf1iRKYRIE8BejD+ZJmV/l/86JxtnJ0w==";

        String decryptedMessage = aes.decryptMessage(encryptMessage);
        log.info("\nDecrypted Message: {}",decryptedMessage);

//        aes.getKeys(); //generete a key

    }


}
