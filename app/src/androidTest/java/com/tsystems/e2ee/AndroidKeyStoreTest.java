package com.tsystems.e2ee;

import android.content.Context;

import com.tsystems.e2ee.android.AndroidKeyStore;
import com.tsystems.e2ee.crypto.CryptographyException;

import androidx.test.InstrumentationRegistry;
import androidx.test.runner.AndroidJUnit4;

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

import static org.junit.Assert.*;

/**
 * Instrumented test, which will execute on an Android device.
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
@RunWith(AndroidJUnit4.class)
public class AndroidKeyStoreTest {

    @Test
    public void useAppContext() {
        // Context of the app under test.
        Context appContext = InstrumentationRegistry.getTargetContext();

        assertEquals("com.tsystems.e2ee", appContext.getPackageName());
    }

    @Test
    public void testInitialKeyStore(){
        Context appContext = InstrumentationRegistry.getTargetContext();
        AndroidKeyStore androidKeyStore = AndroidKeyStore.getInstance(appContext);
        androidKeyStore.createNewKeyPair("Test");
        assertEquals("keypair generated", true, androidKeyStore.keypairExist("Test"));

    }

    @Test
    public void testEncryptDecryptMessage() throws UnsupportedEncodingException, CryptographyException {
        String testText = "Hello World!";
        String keyAlias = "Test";
        Context appContext = InstrumentationRegistry.getTargetContext();
        AndroidKeyStore androidKeyStore = AndroidKeyStore.getInstance(appContext);
        androidKeyStore.eraseKey(keyAlias);
        androidKeyStore.createNewKeyPair(keyAlias);
        assertEquals("keypair generated", true, androidKeyStore.keypairExist(keyAlias));
        byte[] encrypted = androidKeyStore.encrypt(androidKeyStore.getPublicKeyByAlias(keyAlias),testText.getBytes("UTF-8"));
        byte[] decrypted = androidKeyStore.decrypt(androidKeyStore.getPrivateKeyByAlias(keyAlias), encrypted);
        assertEquals("message encrypted and decrypted", testText, new String(decrypted, "UTF-8"));
    }

    @Test
    public void testSignature() throws UnsupportedEncodingException, CryptographyException {
        String testText = "Hello World!";
        String keyAlias = "Test";
        Context appContext = InstrumentationRegistry.getTargetContext();
        AndroidKeyStore androidKeyStore = AndroidKeyStore.getInstance(appContext);
        androidKeyStore.eraseKey(keyAlias);
        androidKeyStore.createNewKeyPair(keyAlias);
        assertEquals("keypair generated", true, androidKeyStore.keypairExist(keyAlias));
        byte[] singed = androidKeyStore.sign(androidKeyStore.getPrivateKeyByAlias(keyAlias),testText.getBytes("UTF-8"));
        boolean isValid = androidKeyStore.verify(androidKeyStore.getPublicKeyByAlias(keyAlias), singed, testText.getBytes("UTF-8"));
        assertEquals("signature is valid", true, isValid);

    }

    @Test
    public void testSymmetricCrypt() throws IOException, CryptographyException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException, UnrecoverableEntryException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchProviderException, SignatureException, KeyStoreException, IllegalBlockSizeException {
        String testText = "Hello World!";
        String keyAlias = "Test6";
        Context appContext = InstrumentationRegistry.getTargetContext();
        AndroidKeyStore androidKeyStore = AndroidKeyStore.getInstance(appContext);
        androidKeyStore.eraseKey(keyAlias);
        androidKeyStore.generateSecretKey(keyAlias);
        assertEquals("keypair generated", true, androidKeyStore.secretKeyExist(keyAlias));
        byte[] encrypted = androidKeyStore.symmetricEncryptMessage(keyAlias,testText);
        String decrypted = androidKeyStore.symmetricDecryptMessage(keyAlias, encrypted);
        assertEquals("message encrypted", testText, decrypted);

    }
}
