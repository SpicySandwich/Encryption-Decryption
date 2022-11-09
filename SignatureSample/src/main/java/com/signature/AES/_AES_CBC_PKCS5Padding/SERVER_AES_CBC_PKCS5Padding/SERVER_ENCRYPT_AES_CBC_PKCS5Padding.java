package com.signature.AES._AES_CBC_PKCS5Padding.SERVER_AES_CBC_PKCS5Padding;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

@Slf4j
@Service
public class SERVER_ENCRYPT_AES_CBC_PKCS5Padding {
    private static final String secretKeyWord = "conred_secretKey";
    private static final String secretKeyEncoded = "Y29ucmVkX3NlY3JldEtleQ==";

    private SecureRandom secureRandom = new SecureRandom();

    private IvParameterSpec IV;

    private IvParameterSpec generateIV() {

        byte[] genIV = secureRandom.generateSeed(16);
        secureRandom.setSeed(genIV);
        byte[] randomByteIV = new byte[16];
        secureRandom.nextBytes(randomByteIV);
        IV = new IvParameterSpec(randomByteIV);
        return IV;
    }
    //can use generateIV().getIV() directly // what if its a string being pass is IV to IvParameterSpec
    public String enCodeIV(){
        String StringIV = Base64.getEncoder().encodeToString(generateIV().getIV());
        log.info("IV to string: {}",StringIV);
        //output: sample random generated IV: b2qdXV62+MFW7dWysGUhyw==
        return  StringIV;
    }
    public String wordSecretKeyToEncoded(){
        String secretKey1= Base64.getEncoder().encodeToString(secretKeyWord.getBytes());
        log.info("IV to secretKey1: {}",secretKey1);
        //output: Y29ucmVkX3NlY3JldEtleQ==
        return secretKey1;
    }
    public StudentEncryptedInfo encrypt(String message){

        String iv = enCodeIV();

        try {
            byte[] bytesIV = Base64.getDecoder().decode(iv);
            byte[] bytesSecretKey = Base64.getDecoder().decode(wordSecretKeyToEncoded());

            IvParameterSpec ivSpec = new IvParameterSpec(bytesIV);
            SecretKeySpec keySpec = new SecretKeySpec(bytesSecretKey, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            byte[] encryptByteMessage = cipher.doFinal(message.getBytes());
            String encryptMessage = Base64.getEncoder().encodeToString(encryptByteMessage);

            StudentEncryptedInfo studentEncryptedInfo =  StudentEncryptedInfo.builder()
                    .encryptedInfo(encryptMessage)
                    .iv(iv)
                    .build();
            return studentEncryptedInfo;
        }catch (Exception e){
            e.printStackTrace();
        }

        return null;

    }

//    public static void main(String[] args) {
//        SERVER_ENCRYPT_AES_CBC_PKCS5Padding ts = new SERVER_ENCRYPT_AES_CBC_PKCS5Padding();
//
//        String data = ts.encrypt("This is Conred");
//        log.info("Encrypted Message: {}",data);
//
////        ts.enCodeIV();
////        ts.wordSecretKeyToEncoded();
//
//    }
}
