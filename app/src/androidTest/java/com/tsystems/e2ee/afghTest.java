package com.tsystems.e2ee;

import android.content.Context;
import android.util.Base64;

import com.tsystems.e2ee.android.AndroidKeyStore;
import com.tsystems.e2ee.crypto.CryptographyException;
import com.tsystems.e2ee.crypto.Tuple;
import com.tsystems.e2ee.crypto.afgh.AFGHCryptoFactory;
import com.tsystems.e2ee.crypto.afgh.AFGHCryptoParameters;
import com.tsystems.e2ee.crypto.afgh.AFGHKeyPair;
import com.tsystems.e2ee.crypto.nics.AFGHGlobalParameters;
import com.tsystems.e2ee.crypto.nics.AFGHProxyFactory;
import com.tsystems.e2ee.crypto.nics.AFGHProxyReEncryption;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import androidx.test.InstrumentationRegistry;
import androidx.test.runner.AndroidJUnit4;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.ElementPowPreProcessing;
import it.unisa.dia.gas.jpbc.PairingPreProcessing;
import it.unisa.dia.gas.jpbc.*;

import static org.junit.Assert.assertEquals;

@RunWith(AndroidJUnit4.class)
public class afghTest {

    private AndroidKeyStore androidKeyStore;
    private String testUserA = "alice";
    private String testUserADEK = "alice_DEK";
    private String testUserB = "bob";

    private AFGHCryptoParameters alice_AFGHCryptoParameters;

    private String cryptoParametersInitalString = null;

    private String testData = " Hello Wold!";


    @Before
    public void setupTestKeyStore() {
        Context appContext = InstrumentationRegistry.getTargetContext();
        androidKeyStore = AndroidKeyStore.getInstance(appContext);
        androidKeyStore.eraseKey(testUserA);
        androidKeyStore.eraseKey(testUserB);
        androidKeyStore.eraseKey(testUserADEK);

        androidKeyStore.createNewKeyPair(testUserA);
        androidKeyStore.createNewKeyPair(testUserB);
        androidKeyStore.generateSecretKey(testUserADEK);


        alice_AFGHCryptoParameters = new AFGHCryptoParameters(cryptoParametersInitalString);
        cryptoParametersInitalString = alice_AFGHCryptoParameters.toCryptoParametersInitalString();

    }



// test succeed Example using init string for initial AFGHCrypto Parameters
    @Test
    public void testExampleFactory() {



        AFGHCryptoParameters bob_AFGHCryptoParameters = new AFGHCryptoParameters(cryptoParametersInitalString);


        // Secret keys

        byte[] sk_a = AFGHProxyFactory.generateSecretKey(alice_AFGHCryptoParameters).toBytes();


        byte[] sk_b = AFGHProxyFactory.generateSecretKey(bob_AFGHCryptoParameters).toBytes();


        // Public keys

        byte[] pk_a = AFGHProxyFactory.generatePublicKey(sk_a, alice_AFGHCryptoParameters);


        byte[] pk_b = AFGHProxyFactory.generatePublicKey(sk_b,bob_AFGHCryptoParameters);


        // Re-Encryption Key

        byte[] rk_a_b = AFGHProxyFactory.generateReEncryptionKey(pk_b, sk_a, alice_AFGHCryptoParameters);


        String message = "David";
        byte[] m = message.getBytes();


        byte[] c_a = AFGHProxyFactory.secondLevelEncryption(m, pk_a,alice_AFGHCryptoParameters);


        byte[] c_b = AFGHProxyFactory.reEncryption(c_a, rk_a_b,bob_AFGHCryptoParameters);
        ///

        byte[] m2 = AFGHProxyFactory.firstLevelDecryption(c_b, sk_b, bob_AFGHCryptoParameters);
        //System.out.println("m2:" + new String(m2));


        assertEquals("message is equal", message, new String(m2).trim());
    }

    @Test
    public void testExample() {
        int rBits = 256; //160;    // 20 bytes
        int qBits = 1536; //512;    // 64 bytes

        AFGHGlobalParameters global = new AFGHGlobalParameters(rBits, qBits);
        AFGHCryptoFactory alice_AFGHCryptoFactory = new AFGHCryptoFactory(global);
        AFGHCryptoFactory bob_AFGHCryptoFactory = new AFGHCryptoFactory(global);

        // Secret keys

        byte[] sk_a = alice_AFGHCryptoFactory.generateSecretKey();


        byte[] sk_b = alice_AFGHCryptoFactory.generateSecretKey();


        // Public keys

        byte[] pk_a = alice_AFGHCryptoFactory.generatePublicKey(sk_a);


        byte[] pk_b = alice_AFGHCryptoFactory.generatePublicKey(sk_b);


        // Re-Encryption Key

        byte[] rk_a_b = alice_AFGHCryptoFactory.generateReEncryptionKey(pk_b, sk_a);


        String message = "David";
        byte[] m = message.getBytes();


        byte[] c_a = alice_AFGHCryptoFactory.secondLevelEncryption(m, pk_a);


        byte[] c_b = alice_AFGHCryptoFactory.reEncryption(c_a, rk_a_b);
        //System.out.println("cb: " + Arrays.toString(c_b));

        ///


        byte[] m2 = alice_AFGHCryptoFactory.firstLevelDecryption(c_b, sk_b);
        //System.out.println("m2:" + new String(m2));


        assertEquals("message is equal", message, new String(m2).trim());
    }

//    @Test
//    public void testAFGHAlgorithm() throws IOException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException, UnrecoverableEntryException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchProviderException, SignatureException, KeyStoreException, IllegalBlockSizeException, CryptographyException {
//        int rBits = 256; //160;    // 20 bytes
//        int qBits = 1536; //512;    // 64 bytes
//
//        AFGHGlobalParameters global = new AFGHGlobalParameters(rBits, qBits);
//
//        AFGHCryptoFactory alice_AFGHCryptoFactory = new AFGHCryptoFactory(global);
//        AFGHKeyPair alice_AFGHKeyPair = alice_AFGHCryptoFactory.generateAFGHKeyPair();
//
//        byte[] encryptedMessage = androidKeyStore.symmetricEncryptMessage(testUserADEK, testData);
//        byte[] encryptedDEK = alice_AFGHCryptoFactory.secondLevelEncryption(androidKeyStore.getSecretKeyByAlias(testUserADEK).getEncoded(), alice_AFGHKeyPair.getPublicKey());
//        byte[] encrypted_afgh_sk = androidKeyStore.encrypt(androidKeyStore.getPublicKeyByAlias(testUserA), alice_AFGHKeyPair.getSecretKey());
//
//
//        AFGHCryptoFactory bob_AFGHCryptoFactory = new AFGHCryptoFactory(global);
//        AFGHKeyPair bob_AFGHKeyPair = bob_AFGHCryptoFactory.generateAFGHKeyPair();
//
//        // verify permission request of b
//        //1. create signature
//        byte[] sign = androidKeyStore.sign(androidKeyStore.getPrivateKeyByAlias(testUserB), bob_AFGHKeyPair.getPublicKey());
//        boolean verified = androidKeyStore.verify(androidKeyStore.getPublicKeyByAlias(testUserB), sign, bob_AFGHKeyPair.getPublicKey());
//        assertEquals("signature of bob should be valid", true, verified);
//
//        //2. bob request permission -> get reencryption key
//
//        byte[] descrypted_afgh_sk = androidKeyStore.decrypt(androidKeyStore.getPrivateKeyByAlias(testUserA), encrypted_afgh_sk);
//        byte[] reencryption_key_bob = alice_AFGHCryptoFactory.generateReEncryptionKey(bob_AFGHKeyPair.getPublicKey(), descrypted_afgh_sk);
//
//        //3. reencryption
//        byte[] reEncryptionDEK_Bob = alice_AFGHCryptoFactory.reEncryption(encryptedDEK, reencryption_key_bob);
//
//        //4. first level decryption
//        byte[] decryptedDEK_bob = bob_AFGHCryptoFactory.firstLevelDecryption(reEncryptionDEK_Bob, bob_AFGHKeyPair.getSecretKey());
//
//        //5. use decrypted key
//        String testData2 = androidKeyStore.symmetricDecryptMessage(androidKeyStore.bytesToSecretKey(decryptedDEK_bob), encryptedMessage);
//
//        assertEquals("message be the same", testData, testData2);
//
//
//    }

//    @Test
//    public void testAFGHAlgorithm() throws IOException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException, UnrecoverableEntryException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchProviderException, SignatureException, KeyStoreException, IllegalBlockSizeException, CryptographyException {
//        AFGHCryptoFactory alice_AFGHCryptoFactory = new AFGHCryptoFactory(alice_AFGHCryptoParameters);
//        AFGHKeyPair alice_AFGHKeyPair = alice_AFGHCryptoFactory.generateAFGHKeyPair();
//
//        byte[] encryptedMessage = androidKeyStore.symmetricEncryptMessage(testUserADEK, testData);
//        byte[] encryptedDEK = alice_AFGHCryptoFactory.secondLevelEncryption(androidKeyStore.getSecretKeyByAlias(testUserADEK).getEncoded(), alice_AFGHKeyPair.getPublicKey());
//        byte[] encrypted_afgh_sk = androidKeyStore.encrypt(androidKeyStore.getPublicKeyByAlias(testUserA), alice_AFGHKeyPair.getSecretKey());
//
//
//        AFGHCryptoFactory bob_AFGHCryptoFactory = new AFGHCryptoFactory(new AFGHCryptoParameters(cryptoParametersInitalString));
//        AFGHKeyPair bob_AFGHKeyPair = bob_AFGHCryptoFactory.generateAFGHKeyPair();
//
//        // verify permission request of b
//        //1. create signature
//        byte[] sign = androidKeyStore.sign(androidKeyStore.getPrivateKeyByAlias(testUserB), bob_AFGHKeyPair.getPublicKey());
//        boolean verified = androidKeyStore.verify(androidKeyStore.getPublicKeyByAlias(testUserB), sign, bob_AFGHKeyPair.getPublicKey());
//        assertEquals("signature of bob should be valid", true, verified);
//
//        //2. bob request permission -> get reencryption key
//
//        byte[] descrypted_afgh_sk = androidKeyStore.decrypt(androidKeyStore.getPrivateKeyByAlias(testUserA), encrypted_afgh_sk);
//        byte[] reencryption_key_bob = alice_AFGHCryptoFactory.generateReEncryptionKey(bob_AFGHKeyPair.getPublicKey(), descrypted_afgh_sk);
//
//        //3. reencryption
//        byte[] reEncryptionDEK_Bob = alice_AFGHCryptoFactory.reEncryption(encryptedDEK, reencryption_key_bob);
//
//        //4. first level decryption
//        byte[] decryptedDEK_bob = bob_AFGHCryptoFactory.firstLevelDecryption(reEncryptionDEK_Bob, bob_AFGHKeyPair.getSecretKey());
//
//        //5. use decrypted key
//        String testData2 = androidKeyStore.symmetricDecryptMessage(androidKeyStore.bytesToSecretKey(decryptedDEK_bob), encryptedMessage);
//
//        assertEquals("message be the same", testData, testData2);
//
//
//    }


//todo fix with test Example factory
//    @Test
//    public void testAFGHAlgorithmSimple() throws IOException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException, UnrecoverableEntryException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchProviderException, SignatureException, KeyStoreException, IllegalBlockSizeException, CryptographyException {
//        int rBits = 256; //160;    // 20 bytes
//        int qBits = 1536; //512;    // 64 bytes
//
//        AFGHGlobalParameters global = new AFGHGlobalParameters(rBits, qBits);
//
//        AFGHCryptoFactory alice_AFGHCryptoFactory = new AFGHCryptoFactory(global);
//        AFGHKeyPair alice_AFGHKeyPair = alice_AFGHCryptoFactory.generateAFGHKeyPair();
//
//      //  byte[] encryptedMessage = androidKeyStore.symmetricEncryptMessage(testUserADEK, testData);
//        byte[] encryptedDEK = alice_AFGHCryptoFactory.secondLevelEncryption(testData.getBytes("UTF-8"), alice_AFGHKeyPair.getPublicKey());
//        byte[] encrypted_afgh_sk = androidKeyStore.encrypt(androidKeyStore.getPublicKeyByAlias(testUserA), alice_AFGHKeyPair.getSecretKey());
//
//
//        AFGHCryptoFactory bob_AFGHCryptoFactory = new AFGHCryptoFactory(global);
//        AFGHKeyPair bob_AFGHKeyPair = bob_AFGHCryptoFactory.generateAFGHKeyPair();
//
//        // verify permission request of b
//        //1. create signature
//        byte[] sign = androidKeyStore.sign(androidKeyStore.getPrivateKeyByAlias(testUserB), bob_AFGHKeyPair.getPublicKey());
//        boolean verified = androidKeyStore.verify(androidKeyStore.getPublicKeyByAlias(testUserB), sign, bob_AFGHKeyPair.getPublicKey());
//        assertEquals("signature of bob should be valid", true, verified);
//
//        //2. bob request permission -> get reencryption key
//
//        byte[] descrypted_afgh_sk = androidKeyStore.decrypt(androidKeyStore.getPrivateKeyByAlias(testUserA), encrypted_afgh_sk);
//        byte[] reencryption_key_bob = alice_AFGHCryptoFactory.generateReEncryptionKey(bob_AFGHKeyPair.getPublicKey(), descrypted_afgh_sk);
//
//        //3. reencryption
//        byte[] reEncryptionDEK_Bob = alice_AFGHCryptoFactory.reEncryption(encryptedDEK, reencryption_key_bob);
//
//        //4. first level decryption
//        byte[] decryptedDEK_bob = bob_AFGHCryptoFactory.firstLevelDecryption(reEncryptionDEK_Bob, bob_AFGHKeyPair.getSecretKey());
//
//        //5. use decrypted key
//        String testData2 = new String(decryptedDEK_bob).trim();
//
//        assertEquals("message be the same", testData, testData2);
//
//
//    }




//
//    succeed
//    @Test
//    public void testBytesExample(){
//
//        int rBits = 256; //160;    // 20 bytes
//        int qBits = 1536; //512;    // 64 bytes
//
//        AFGHGlobalParameters global = new AFGHGlobalParameters(rBits, qBits);
//
//        // Secret keys
//
//        byte[] sk_a = AFGHProxyReEncryption.generateSecretKey(global).toBytes();
//
//
//        byte[] sk_b = AFGHProxyReEncryption.generateSecretKey(global).toBytes();
//
//
//        // Public keys
//
//        byte[] pk_a = AFGHProxyReEncryption.generatePublicKey(sk_a, global);
//
//
//        byte[] pk_b = AFGHProxyReEncryption.generatePublicKey(sk_b, global);
//
//
//        // Re-Encryption Key
//
//        byte[] rk_a_b = AFGHProxyReEncryption.generateReEncryptionKey(pk_b, sk_a, global);
//
//
//        String message = "David";
//        byte[] m = message.getBytes();
//
//
//        byte[] c_a = AFGHProxyReEncryption.secondLevelEncryption(m, pk_a, global);
//
//
//        byte[] c_b = AFGHProxyReEncryption.reEncryption(c_a, rk_a_b, global);
//        //System.out.println("cb: " + Arrays.toString(c_b));
//
//        ///
//
//
//        byte[] m2 = AFGHProxyReEncryption.firstLevelDecryption(c_b, sk_b, global);
//        //System.out.println("m2:" + new String(m2));
//
//
//        assertEquals("message is equal", message, new String(m2).trim());
//
//
//
//
//    }
//
//    @Test
//    public void testOrigninalExample(){
//
//        int rBits = 256; //160;    // 20 bytes
//        int qBits = 1536; //512;    // 64 bytes
//
//        AFGHGlobalParameters global = new AFGHGlobalParameters(rBits, qBits);
//
//
//
////        // Secret keys
////
////        byte[] sk_a = AFGH.generateSecretKey(global).toBytes();
////
////        System.out.println(medirTiempo());
////
////        byte[] sk_b = AFGH.generateSecretKey(global).toBytes();
////
////        System.out.println(medirTiempo());
////
////        // Public keys
////
////        byte[] pk_a = AFGH.generatePublicKey(sk_a, global);
////
////        System.out.println(medirTiempo());
////
////        byte[] pk_b = AFGH.generatePublicKey(sk_b, global);
////
////        System.out.println(medirTiempo());
////
////        // Re-Encryption Key
////
////        byte[] rk_a_b = AFGH.generateReEncryptionKey(pk_b, sk_a, global);
////
////        System.out.println(medirTiempo());
////
////        String message = "David";
////        byte[] m = message.getBytes();
////
////        System.out.println(medirTiempo());
////
////        byte[] c_a = AFGH.secondLevelEncryption(m, pk_a, global);
////
////        System.out.println(medirTiempo());
////
////        String c_a_base64 = Base64.encodeBase64URLSafeString(c_a);
////        //System.out.println("c_a_base64 = " + c_a_base64);
////
////        System.out.println(medirTiempo());
////
////        String rk_base64 = Base64.encodeBase64URLSafeString(rk_a_b);
////        //System.out.println("rk_base64 = " + rk_base64);
////        System.out.println(medirTiempo());
////
////        byte[] c, rk;
////        rk = Base64.decodeBase64(rk_base64);
////
////        System.out.println(medirTiempo());
////
////        c = Base64.decodeBase64(c_a_base64);
////
////        System.out.println(medirTiempo());
////
////        byte[] c_b = AFGH.reEncryption(c, rk, global);
////        //System.out.println("cb: " + Arrays.toString(c_b));
////        System.out.println(medirTiempo());
////
////        String c_b_base64 = Base64.encodeBase64URLSafeString(c_b);
////        //System.out.println("c_b_base64 = " + c_b_base64);
////
////        System.out.println(medirTiempo());
////
////        c = Base64.decodeBase64(c_b_base64);
////
////        System.out.println(medirTiempo());
////
////        byte[] m2 = AFGH.firstLevelDecryption(c_b, sk_b, global);
////        //System.out.println("m2:" + new String(m2));
////
////        System.out.println(medirTiempo());
////
////        assert message.equals(new String(m2).trim());
////
////        System.out.println();
////        System.out.println(global.toBytes().length);
////        System.out.println(sk_a.length);
////        System.out.println(sk_b.length);
////        System.out.println(pk_a.length);
////        System.out.println(pk_b.length);
////        System.out.println(rk_a_b.length);
////        System.out.println(m.length);
////        System.out.println(c_a.length);
////        System.out.println(c_b.length);
////
////        //
////        Map<String, byte[]> map = new HashMap<String, byte[]>();
////        map.put("sk_a", sk_a);
////        map.put("sk_b", sk_b);
////        map.put("pk_a", pk_a);
////        map.put("pk_b", pk_b);
////        map.put("rk_a_b", rk_a_b);
////        map.put("global", global.toBytes());
////        map.put("c_a_base64", c_a_base64.getBytes());
////
////        ObjectOutputStream fos = new ObjectOutputStream(new FileOutputStream("/Users/david/Desktop/pre.object"));
////        fos.writeObject(map);
////        fos.close();
//        //
//
//        // Secret keys
//
//        Element sk_a = AFGHProxyReEncryption.generateSecretKey(global);
//
//
//
//        Element sk_b = AFGHProxyReEncryption.generateSecretKey(global);
//
//
//
//        Element sk_b_inverse = sk_b.invert();
//
//
//
//        // Public keys
//
//        Element pk_a = AFGHProxyReEncryption.generatePublicKey(sk_a, global);
//
//
//
//        Element pk_b = AFGHProxyReEncryption.generatePublicKey(sk_b, global);
//
//
//
//        ElementPowPreProcessing pk_a_ppp = pk_a.getElementPowPreProcessing();
//
//
//
//        // Re-Encryption Key
//
//        Element rk_a_b = AFGHProxyReEncryption.generateReEncryptionKey(pk_b, sk_a);
//
//
//
//        String message = "12345678901234567890123456789012";
//        Element m = AFGHProxyReEncryption.stringToElement(message, global.getG2());
//
//
//
//        Tuple c_a = AFGHProxyReEncryption.secondLevelEncryption(m, pk_a_ppp, global);
//
//
//
//        PairingPreProcessing e_ppp = global.getE().getPairingPreProcessingFromElement(rk_a_b);
//
//
//
//        Tuple c_b = AFGHProxyReEncryption.reEncryption(c_a, rk_a_b, e_ppp);
//
//
//
//        Element m2 = AFGHProxyReEncryption.firstLevelDecryptionPreProcessing(c_b, sk_b_inverse, global);
//
//        assertEquals("message is equal", message, new String(m2.toBytes()).trim());
//
//
//
//
//    }
}
