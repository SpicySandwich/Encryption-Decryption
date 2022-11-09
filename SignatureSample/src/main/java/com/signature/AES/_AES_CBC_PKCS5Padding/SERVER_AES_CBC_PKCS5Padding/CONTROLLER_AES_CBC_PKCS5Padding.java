package com.signature.AES._AES_CBC_PKCS5Padding.SERVER_AES_CBC_PKCS5Padding;

import com.google.gson.Gson;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/encryption")
@Slf4j
public class CONTROLLER_AES_CBC_PKCS5Padding {

    @Autowired
    private SERVER_ENCRYPT_AES_CBC_PKCS5Padding encrypt;

    @Autowired
    private SERVER_DECRYPT_AES_CBC_PKCS5Padding decrypt;
    @Autowired
    private Gson gson;

    @PostMapping("/ENCRYPT_AES_CBC_PKCS5Padding")
    public ResponseEntity<StudentEncryptedInfo> encryptInfo(@RequestBody StudentInfo studentInfo){
        String data = gson.toJson(studentInfo);
        StudentEncryptedInfo encryptedRequest = encrypt.encrypt(data);
         return new ResponseEntity<>(encryptedRequest, HttpStatus.OK);
    }

    @PostMapping("/DECRYPT_AES_CBC_PKCS5Padding")
    public ResponseEntity<StudentInfo> decryptInfo(@RequestBody StudentEncryptedInfo studentEncryptedInfo){
     String data = decrypt.aesDecryption(studentEncryptedInfo.getEncryptedInfo(),studentEncryptedInfo.getIv());
     log.info("Decrypted Data: {}",data);
        StudentInfo studentInfo = gson.fromJson(data,StudentInfo.class);
        return new ResponseEntity<>(studentInfo,HttpStatus.OK);

    }
}

@Data
@AllArgsConstructor
@NoArgsConstructor
@Component
@Builder
class StudentEncryptedInfo{
    private String encryptedInfo;
    private String iv;
}
@Data
@AllArgsConstructor
@NoArgsConstructor
@Component
@Builder
class StudentInfo{
    private String studentFullName;
    private String studentLocation;
}





