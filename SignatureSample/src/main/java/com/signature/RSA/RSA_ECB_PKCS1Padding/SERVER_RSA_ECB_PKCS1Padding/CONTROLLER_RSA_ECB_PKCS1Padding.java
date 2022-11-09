package com.signature.RSA.RSA_ECB_PKCS1Padding.SERVER_RSA_ECB_PKCS1Padding;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;


import java.util.Map;

@Slf4j
@RestController
public class CONTROLLER_RSA_ECB_PKCS1Padding {

    @Autowired
    private PUBLIC_KEY_RSA_ECB_PKCS1Padding service_rsa_ecb_pkcs1Padding;

    @Autowired
    private PRIVATE_KEY_DECRYPT_RSA_ECB_PKCS1Padding privatekey_decrypt_rsa_ecb_pkcs1Padding;

    @GetMapping(path = "/encryptedMessage")
    @ResponseBody
    public String getEncryptedMessage(@RequestBody Map<String, ?> input) throws JsonProcessingException {
        service_rsa_ecb_pkcs1Padding.initFromString();
        ObjectMapper objectMapper = new ObjectMapper();
        String encryptedMessage = service_rsa_ecb_pkcs1Padding.encrypt(input.get("input").toString());
        return encryptedMessage;

    }
    @GetMapping("/decryptedMessage")
    public String getDecryptedMessage(@RequestParam String input){
        privatekey_decrypt_rsa_ecb_pkcs1Padding.initFromString();
        String decryptedMessage = privatekey_decrypt_rsa_ecb_pkcs1Padding.decrypt(input.replace(" ","+"));
        return  decryptedMessage;
    }
}
