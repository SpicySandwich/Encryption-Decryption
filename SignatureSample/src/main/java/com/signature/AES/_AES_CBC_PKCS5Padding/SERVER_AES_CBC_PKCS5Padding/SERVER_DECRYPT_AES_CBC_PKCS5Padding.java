package com.signature.AES._AES_CBC_PKCS5Padding.SERVER_AES_CBC_PKCS5Padding;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

@Slf4j
@Service
public class SERVER_DECRYPT_AES_CBC_PKCS5Padding {

    private static final String secretKeyWord = "conred_secretKey";
    private static final String secretKeyEncoded = "Y29ucmVkX3NlY3JldEtleQ==";

    public String aesDecryption (String cipherText,String IV) {

        try {

            byte[] secretKey= Base64.getDecoder().decode(secretKeyEncoded);
            byte[] IVs = Base64.getDecoder().decode(IV);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec keySpec = new SecretKeySpec(secretKey, "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(IVs);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            byte[] decryptedText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
            return new String(decryptedText);

        }catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }
}
