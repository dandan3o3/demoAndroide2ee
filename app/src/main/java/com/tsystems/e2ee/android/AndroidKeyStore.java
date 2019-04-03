package com.tsystems.e2ee.android;

import android.content.Context;
import android.security.KeyPairGeneratorSpec;
import android.util.Log;

import com.tsystems.e2ee.crypto.CryptographyException;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

public class AndroidKeyStore {
  static final String TAG = "AndroidKeyStore";
  private final Context context;
  private static final Map<String, KeyPair> masterKeyPairs = new HashMap<>();
  private static final Map<String, SecretKey> secretKeys = new HashMap<>();


  KeyStore keyStore;
  private static  AndroidKeyStore ANDROID_KEYSTORE_INSTANCE = null;
  private static Cipher cipher = null;
  private static Signature signGen = null;


  private String symmetricCipherName = "AES/GCM/NoPadding";
  private String symmetricCipherProvider = "BC";
  private int symmetricKeyLength = 128;

  private String symmetricKeyGeneratorName = "AES";
  private String symmetricKeyGeneratorProvider = "BC";


    private static final int GCM_TAG_LENGTH = 16;
    private static final int GCM_NONCE_LENGTH = 12;


    private String asymmetricCipherName = "RSA/ECB/PKCS1Padding";
  private String asymmetricCipherProvider = "AndroidOpenSSL";// dont uese it on andorid 6


  private String signatureName = "SHA256withRSA";
  private String signatureProvider = "BC";


  private AndroidKeyStore(Context context) {
    this.context = context;
    try {
      keyStore = KeyStore.getInstance("AndroidKeyStore");
      keyStore.load(null);
      
    } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
      e.printStackTrace();
    }
  }


  public void eraseKey(String alias){
    try {
      keyStore.deleteEntry(alias);
    } catch (KeyStoreException e) {
      e.printStackTrace();
    }
  }

  public static AndroidKeyStore getInstance(Context context) {

    if (ANDROID_KEYSTORE_INSTANCE == null) {
      synchronized(AndroidKeyStore.class) {
        ANDROID_KEYSTORE_INSTANCE = new AndroidKeyStore(context);

      }
    }
    return ANDROID_KEYSTORE_INSTANCE;
  }


  public SecretKey generateSecretKey(final String alias)  {


    try {
      final KeyGenerator keyGenerator = KeyGenerator
              .getInstance(symmetricKeyGeneratorName);
      SecretKey secretKey = keyGenerator.generateKey();
//      KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
//      keyStore.setEntry(alias, secretKeyEntry,null);
      secretKeys.put(alias, secretKey);

      return secretKey;
    } catch ( NoSuchAlgorithmException e) {
      e.printStackTrace();
    }

    return null;
  }

  public SecretKey bytesToSecretKey(byte[] bytes){
    SecretKey originalKey = new SecretKeySpec(bytes, 0, bytes.length, "AES");
    return originalKey;

  }

  public byte[] symmetricEncryptMessage(final String alias, final String textToEncrypt)
          throws UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException,
          NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IOException,
          InvalidAlgorithmParameterException, SignatureException, BadPaddingException,
          IllegalBlockSizeException {

    final byte[] nonce = new byte[GCM_NONCE_LENGTH];
    SecureRandom random = new SecureRandom();
    synchronized (random){
      random.nextBytes(nonce);
    }

    GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH*8, nonce);
    final Cipher cipher = Cipher.getInstance(symmetricCipherName);
    cipher.init(Cipher.ENCRYPT_MODE, getSecretKeyByAlias(alias), spec);

    byte[] encryption  = cipher.doFinal(textToEncrypt.getBytes("UTF-8"));
    return new EncryptedAEADChunk(encryption,nonce).toByteArray();

  }

  public String symmetricDecryptMessage(final SecretKey secretKey, final byte[] encrypted){
    final Cipher cipher;
    try {
      EncryptedAEADChunk encryptedAEADChunk = EncryptedAEADChunk.fromByteArray(encrypted);
      GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH*8, encryptedAEADChunk.getNonce());
      cipher = Cipher.getInstance(symmetricCipherName);
      cipher.init(Cipher.DECRYPT_MODE, secretKey,spec);
      if(encryptedAEADChunk.getAad() != null){
        cipher.updateAAD(encryptedAEADChunk.getAad());
      }

      return new String(cipher.doFinal(encryptedAEADChunk.getEncryptedData()), "UTF-8");
    } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
      e.printStackTrace();
    } catch (NoSuchPaddingException e) {
      e.printStackTrace();
    } catch (BadPaddingException e) {
      e.printStackTrace();
    } catch (UnsupportedEncodingException e) {
      e.printStackTrace();
    } catch (IllegalBlockSizeException e) {
      e.printStackTrace();
    } catch (InvalidKeyException e) {
      e.printStackTrace();
    }
    return null;
  }

  public String symmetricDecryptMessage(final String alias, final byte[] encrypted){

    SecretKey secretKey = getSecretKeyByAlias(alias);
    return symmetricDecryptMessage(secretKey,encrypted);
  }

  public SecretKey getSecretKeyByAlias(String alias){
    if(secretKeys.containsKey(alias)){
      return secretKeys.get(alias);
    }else {
      try {
        final KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore
                .getEntry(alias, null);

        final SecretKey secretKey = secretKeyEntry.getSecretKey();
        return secretKey;
      } catch (KeyStoreException e) {
        e.printStackTrace();
      } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
      } catch (UnrecoverableEntryException e) {
        e.printStackTrace();
      }
    }
    return null;
  }

  public PublicKey getPublicKeyByAlias(String alias){

    if(masterKeyPairs.containsKey(alias)){
      return masterKeyPairs.get(alias).getPublic();
    }else {
      KeyStore.PrivateKeyEntry privateKeyEntry = null;
      try {
        privateKeyEntry = (KeyStore.PrivateKeyEntry)keyStore.getEntry(alias, null);
        PublicKey publicKey = privateKeyEntry.getCertificate().getPublicKey();
        return publicKey;
      } catch (KeyStoreException e) {
        e.printStackTrace();
      } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
      } catch (UnrecoverableEntryException e) {
        e.printStackTrace();
      }
      return null;
    }
  }

  public PrivateKey getPrivateKeyByAlias(String alias){

    if(masterKeyPairs.containsKey(alias)){
      return masterKeyPairs.get(alias).getPrivate();
    }else {
      KeyStore.PrivateKeyEntry privateKeyEntry = null;
      try {
        privateKeyEntry = (KeyStore.PrivateKeyEntry)keyStore.getEntry(alias, null);
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();
        return privateKey;
      } catch (KeyStoreException e) {
        e.printStackTrace();
      } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
      } catch (UnrecoverableEntryException e) {
        e.printStackTrace();
      }
      return null;
    }

  }

  public boolean keypairExist(String alias){
    return masterKeyPairs.containsKey(alias);
  }

  public boolean secretKeyExist(String alias){
    return secretKeys.containsKey(alias);
  }

  public KeyPair createNewKeyPair(String alias) {
    try {
      // Create new key if needed
      if (!keyStore.containsAlias(alias)) {
        Calendar start = Calendar.getInstance();
        Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 1);
        KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(context)
                .setAlias(alias)
                .setStartDate(start.getTime())
                .setEndDate(end.getTime())
                .setSubject(new X500Principal("CN=Sample Name, O=Android Authority"))
                .setSerialNumber(BigInteger.ONE)
                .build();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
        generator.initialize(spec);

        KeyPair keyPair = generator.generateKeyPair();
        masterKeyPairs.put(alias,keyPair);
        return keyPair;
      }
    } catch (Exception e) {
      Log.e(TAG, Log.getStackTraceString(e));
    }
    return null;
  }

  public synchronized byte[] encrypt(PublicKey key, byte[] message) throws CryptographyException {
    try {
      if(cipher == null){
        cipher = Cipher.getInstance(
                asymmetricCipherName);
      }
      cipher.init(Cipher.ENCRYPT_MODE, key);
      return cipher.doFinal(message);
    } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
      throw new CryptographyException(e.getMessage(), e);
    } catch (NoSuchPaddingException e) {
      e.printStackTrace();
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
    }
    return null;
  }

  public synchronized byte[] decrypt(PrivateKey key, byte[] message) throws CryptographyException {
    try {
      if(cipher == null){
        cipher = Cipher.getInstance(
                asymmetricCipherName,
                asymmetricCipherProvider);
      }
      cipher.init(Cipher.DECRYPT_MODE, key);
      return cipher.doFinal(message);
    } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException e) {
      throw new CryptographyException(e.getMessage(), e);
    }
  }

  public byte[] sign(PrivateKey key, byte[]... content) throws CryptographyException {
    try {
      if(signGen == null){
        signGen = Signature.getInstance(
                signatureName);
      }
      synchronized (signGen) {
        signGen.initSign(key);
        for (byte[] c:content) {
          signGen.update(c);
        }
        return signGen.sign();
      }
    } catch (SignatureException | InvalidKeyException | NoSuchAlgorithmException e) {
      throw new CryptographyException(e.getMessage(), e);
    }
  }

  public boolean verify(PublicKey key, byte[] signature, byte[]... content) throws CryptographyException {
    try {
      if(signGen == null){
        signGen = Signature.getInstance(
                signatureName);
      }
      synchronized (signGen) {
        signGen.initVerify(key);
        for (byte[] c:content) {
          signGen.update(c);
        }
        return signGen.verify(signature);
      }
    } catch (SignatureException | InvalidKeyException | NoSuchAlgorithmException e) {
      throw new CryptographyException(e.getMessage(), e);
    }
  }

}
