package com.signature.RSA.RSA_ECB_PKCS1Padding.SERVER_RSA_ECB_PKCS1Padding;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

@Data
@Slf4j
@Service
public class PRIVATE_KEY_DECRYPT_RSA_ECB_PKCS1Padding {
    private PrivateKey privateKey;
    private final static String PRIVATE_KEY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCLkLyjyVn7TQqZasnRbKrsEcvtSk0KaRwcydXpnN+K2x4oAbk6S/jqrATYviykUrHRUtApEUhh1vSQERVw+wFm/osKtOL5VUFC8XS/zWCCGYZmqP4FWBy6K2MBKcBM28/weVHohIW7YKnLYpTH93htNUBc4SPH9EJTQR+4QaP1/Z3TW4YE8PQ/DP+NwB2L6p/cWBh+MuZD6dzRHJH2ZwXxLvBfBAa0jfbrkX6kGg9qr3NK7s16fhRK+FGmGW9K5easQOQ7swDgk31vsvh/Hfhsv48VT4rYDBXZdobmF/pZ6uCJbY+r7qbUgjPSvuhFCjelDWRGRJNKqqaGLQHPJfijAgMBAAECggEAA1devMkYR2TryQp+dG4WlXpDmJW7zHEBxEqsvWANFgTy7uBDr/qbpfqiTxIWfYShTzKdWy5XvkfoKP7PtZm8ydt0Nrhn6rI40sJ3GhRvqA22YwTOuBAI+AgL4b4/JVfp3Yb6CAgML5U722urxjHNh0fMF60oLyRQ5i9b9AxWQZBcuud26djLCgFrFHBdljpCzR8ebiqjKQrkLhGGAVN/zNfik70T/QqjlqCR3kMWzLfPLip9QE4d4RZH0L9huj4F3b1WlMFUG8XjTGQ8TW96hSsUaZnj5iQvq9FPWXe2n2OTFFAUWM/0pCDMEqs8HL4BSxdARuamkZsmUPBY4GumwQKBgQDRT3PlyBqigcX49F8UL1DmFU3T9Vk5USt0zwD8n7TqfhHChvMMvmekHYYELQkCNh0+JxFjAuF+jIZw5+k/cICnd7/SKdhBM9zksRiFCFn3PzGyPyD5CIlHPnBT053h0vqSTa3SdT4Id6O5yLxJTpZSeWW0Q6dYEzRlUUGbIotvYQKBgQCqsomC+yGOJFIbWAq4VkMVFdwqi5ztH3EIE3OD56nttWindeZFz94aeIXEuxygPsA8Ur7/9NwGSrzI6rL2+J79ABiYVhIVJ5MEDx4sDY/2oUz+LHHfoiNjaHKC5PHXaLjBHgcYmgF4/DTBl0H2lYQK2FqdjFWG4a9ftBO7ZJA6gwKBgGSJbFrntdtuyB/fiTfRzmLlwr9Xrua4FU6DC69MKwMjUPaGCYKKho+u2qtw0k3snjk3XMOZI6S8bOsYidG+AR3viASzsrsG5Ug3xFZJ/6SiBwXeCsFzlzTQSfYJxGEvDMpvY1melRBOHydiwwXXKJ8uzmo6wMuuVdGAqSmR+zWhAoGANdBFY+KyKHKw4+f0sTqYuWwD1fHfzi2sX8RqFXqSattXG/wiVX374lJ+sY/frXE6/4mCp4TVXLJxI9JCC3REAzTljBkOaFbqlUwC0haQfUtKz5LJb5xZFbzW5Qcyaxubq15BFHNw5Wh1ZVa/N/LZBuZAYwzb5cL+m+hUlC5W/esCgYEAmHJtkfVMv/ktqAvBbp/yoozBgMDPotxrbgHlG9MkTM7A0VvKFEMHJ0+sIy9UjK6yrI35zt+IQuQbk7HmNsa0pH1POjDXqO+A5nKyZzm+7UXWBGTX0CPscmLBoAUCsP4NWMJCmxrdiyx0YDSZnCLb1eBCMoghrDsjxgIQvKiP5KY=";


    public void init() {

        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            privateKey = keyPair.getPrivate();
//            log.info("\nPublic Key {}",Base64.getEncoder().encodeToString(publicKey.getEncoded()));
//            log.info("\nPrivate Key {}",Base64.getEncoder().encodeToString(privateKey.getEncoded()));

        } catch (Exception e) {
            e.printStackTrace();
        }
//        keyPairGenerator.initialize(1024);
    }
    public void initFromString(){
        try {
            PKCS8EncodedKeySpec keySpecPrivateKey = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(PRIVATE_KEY));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            privateKey = keyFactory.generatePrivate(keySpecPrivateKey);

        }catch (Exception e){
            e.printStackTrace();
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

}
