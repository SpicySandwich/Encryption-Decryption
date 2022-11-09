package com.signing_and_validating_signatures.DSA;

import org.springframework.beans.factory.annotation.Autowired;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;


public class DSA {

    public static void main(String args[]) {


        try{
            SignerUser  signer = new SignerUser();

            //Remetente Gera Assinatura Digital para uma Mensagem
            String message = "Every sunset give us one day less to live. But every sunrise give uso ne day more to hope.";


            byte[] sign = signMessage(message.getBytes(), signer.getPrivateKey());

            //Guarda Chave Pública para ser Enviada ao Destinatário
            PublicKey pubKey = signer.getPublicKey();

            System.out.println("--- Example with a valid signature ---");
            validateMessageSignature(pubKey, message.getBytes(), sign);

            System.out.println("--- Example with a invalid signature: the message was changed  ---");
            String anotherMessage = "Don't let yesterday take up too much of today.";
            validateMessageSignature(pubKey, anotherMessage.getBytes(), sign);

            String message2 = "The pessimist sees difficulty in every opportunity.";
            PublicKey pubKey2 = signer.getPublicKey();
            byte[] sign2 = signMessage(message2.getBytes(), signer.getPrivateKey());

            System.out.println("--- Example with a invalid signature: using signature that does not match with the current message ---");
            validateMessageSignature(pubKey, message.getBytes(), sign2);

            System.out.println("--- Example with a invalid signature: using public key from another user ---");
            validateMessageSignature(pubKey2, message.getBytes(), sign);

        }catch(Exception e){
            e.printStackTrace();
        }
    }

    public static void validateMessageSignature(PublicKey publicKey, byte[] message, byte[] signature) throws
            NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature clientSig = Signature.getInstance("DSA");
        clientSig.initVerify(publicKey);
        clientSig.update(message);
        if (clientSig.verify(signature)) {
            System.out.println("The message is properly signed.");
        } else {
            System.err.println("It is not possible to validate the signature.");
        }
    }

    public static byte[] signMessage(byte[] message,PrivateKey privateKey) throws NoSuchAlgorithmException,
            InvalidKeyException, SignatureException {
        Signature sig = Signature.getInstance("DSA");
        sig.initSign(privateKey);
        sig.update(message);
        byte[] sign= sig.sign();
        return sign;
    }






}
