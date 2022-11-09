package com.signing_and_validating_signatures.DSA;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.security.SecureRandom;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.NoSuchAlgorithmException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
@Data
@AllArgsConstructor
public class SignerUser {
    private PublicKey publicKey;
    private PrivateKey privateKey;

    public SignerUser() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
        SecureRandom secRan = new SecureRandom();
        kpg.initialize(512, secRan);
        KeyPair keyP = kpg.generateKeyPair();
        this.publicKey= keyP.getPublic();
        this.privateKey = keyP.getPrivate();
    }
}
