/*
 * Copyright (c) 2017 T-Systems
 * All rights reserved.
 *
 * Name: CryptoProvider.java
 * Autor: Jan Starke (jasa)
 * Datum: 16.06.2017
 */

package com.tsystems.e2ee.android;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

/**
 *
 * Represents the results of an AEAD encryption (e.g. AuthenticatedEncryptionStreamCipher-GCM)
 *
 * @author Jan Starke
 * @version 1.0
 */
class EncryptedAEADChunk {
  /**
   * contains the encrypted data
   */
  private byte[] encryptedData;

  /**
   * contains the Nonce; should be completely random data
   */
  private byte[] nonce;

  /**
   * contain the AAD (Additional Authentication Data); may be null
   */
  private byte[] aad;

  /**
   * Constructor. Fills data without aad.
   *
   * @param encryptedData
   *          - Encrypted data.
   * @param nonce
   *          - Random bytes.
   */
  public EncryptedAEADChunk(byte[] encryptedData, byte[] nonce) {
    this.encryptedData = encryptedData;
    this.nonce = nonce;
    this.aad = null;
  }

  /**
   * Constructor. Fills data with aad.
   * 
   * @param encryptedData
   *          - Encrypted data.
   * @param nonce
   *          - Random bytes.
   * @param aad
   *          - Random bytes (Additional Authentication Data).
   */
  public EncryptedAEADChunk(byte[] encryptedData, byte[] nonce, byte[] aad) {
    this.encryptedData = encryptedData;
    this.nonce = nonce;
    this.aad = aad;
  }

  // Setter/getter

  public byte[] getEncryptedData() {
    return encryptedData;
  }

  public byte[] getNonce() {
    return nonce;
  }

  public byte[] getAad() {
    return aad;
  }

  public byte[] toByteArray() {
    final ByteBuffer result =
        aad == null ?
            ByteBuffer.allocate(encryptedData.length + nonce.length + 8) :
            ByteBuffer.allocate(encryptedData.length + nonce.length + aad.length + 12);

    result.putInt(nonce.length);
    result.put(nonce);
    result.putInt(encryptedData.length);
    result.put(encryptedData);
    if (aad != null) {
      result.putInt(aad.length);
      result.put(aad);
    }
    return result.array();
  }

  public static EncryptedAEADChunk fromByteArray(byte[] byteArray) {
    ByteBuffer buffer = ByteBuffer.wrap(byteArray);
    buffer.position(0);

    final int nonce_length = buffer.getInt();
    final byte[] nonce = new byte[nonce_length];
    buffer.get(nonce);


    final int data_length = buffer.getInt();
    final byte[] data = new byte[data_length];
    buffer.get(data);

    if (buffer.position() == byteArray.length) {
      return new EncryptedAEADChunk(data, nonce);
    }

    final int aad_length = buffer.getInt();
    final byte[] aad = new byte[aad_length];
    buffer.get(aad);

    if (buffer.position() == byteArray.length) {
      return new EncryptedAEADChunk(data, nonce, aad);
    }

    throw new BufferUnderflowException();
  }
}
