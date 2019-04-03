package com.tsystems.e2ee.crypto.afgh;

public class AFGHKeyPair {

    byte[] publicKey;
    byte[] secretKey;

    public AFGHKeyPair() {
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    public byte[] getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(byte[] secretKey) {
        this.secretKey = secretKey;
    }

    public AFGHKeyPair(byte[] publicKey, byte[] secretKey) {
        this.publicKey = publicKey;
        this.secretKey = secretKey;
    }
}
