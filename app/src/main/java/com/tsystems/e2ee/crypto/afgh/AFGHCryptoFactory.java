package com.tsystems.e2ee.crypto.afgh;

import com.tsystems.e2ee.crypto.BigIntUtils;
import com.tsystems.e2ee.crypto.Tuple;
import com.tsystems.e2ee.crypto.nics.AFGHGlobalParameters;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.ElementPowPreProcessing;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;

/*
 * Copyright (c) 2018 T-Systems Multimedia Solutions GmbH
 * Riesaer Str. 5, D-01129 Dresden, Germany
 * All rights reserved.
 *
 * Autor: yuti
 * Datum: 23/10/2018
 */
public class AFGHCryptoFactory {

  private final  AFGHGlobalParameters global;

  public AFGHCryptoFactory(AFGHGlobalParameters afghGlobalParameters) {
    this.global = afghGlobalParameters;
  }

  public byte[] secondLevelEncryption(byte[] message, byte[] pk_a) {

    Field G2 = global.getG2();
    Field G1 = global.getG1();

    System.out.println(G2.getClass());

    System.out.println("G2: " + G2.getLengthInBytes());
    // message = m \in G2
    Element m = bytesToElement(message, G2);
    //        System.out.println("M : " + Arrays.toString(m.toBytes()));
    // pk_a \in G1
    Element pk = bytesToElement(pk_a, G1);

    Tuple c = secondLevelEncryption(m, pk, global);

    return mergeByteArrays(c.get(1).toBytes(), c.get(2).toBytes());

  }

  private Tuple secondLevelEncryption(Element m, Element pk_a,final AFGHGlobalParameters global) {

    /*
     * Second Level Encryption
     * c = (c1, c2)     c1 \in G1, c2 \in G2
     *      c1 = g^ak = pk_a^k
     *      c2 = m·Z^k
     */

    //Field G2 = global.getG2();
    Field Zq = global.getZq();

    Pairing e = global.getE();

    Element Z = global.getZ();

    // random k \in Zq
    Element k = Zq.newRandomElement().getImmutable();
    //System.out.println("k = " + elementToString(k));

    // c1 = pk_a^k
    Element c1 = pk_a.powZn(k).getImmutable();

    // c2 = m·Z^k
    Element c2 = m.mul(Z.powZn(k)).getImmutable();

    // c = (c1, c2)
    Tuple c = new Tuple(c1, c2);

    return c;

  }

    public static Element stringToElement(String s, Field G) {
        //System.out.println(s + " = " + Arrays.toString(s.getBytes()));
        //return bytesToElement(Base64.decode(s), G);
        return bytesToElement(s.getBytes(), G);
    }



    public static String elementToString(Element x) {
        //return Base64.encodeBytes(x.toBytes());
        return new String(x.toBytes()).trim();
    }

  private static Element bytesToElement(byte[] b, Field G) {
    int maxLengthBytes = G.getLengthInBytes();

    //System.out.println("maxLengthBytes = " + maxLengthBytes);
    if (b.length > maxLengthBytes) {
      throw new IllegalArgumentException("Input must be less than " + maxLengthBytes + " bytes");
    }
    //System.out.println(Arrays.asList(b));

    Element x = G.newElement();
    x.setFromBytes(b);

    //Element x = G.newElement(new BigInteger(1, b));
    return x.getImmutable();
  }

  public byte[] generateReEncryptionKey(byte[] pk_bytes, byte[] sk_bytes) {
    return generateReEncryptionKey(
        bytesToElement(pk_bytes, global.getG1()),
        bytesToElement(sk_bytes, global.getZq())).toBytes();
  }

  private Element generateReEncryptionKey(Element pk_b, Element sk_a) {

    /*
     * Re-Encryption Key Generation
     */

    // RK(a->b) = pk_b ^(1/sk_a) = g^(b/a)
    Element rk_a_b = pk_b.powZn(sk_a.invert());
    return rk_a_b.getImmutable();

  }

  public byte[] reEncryption(byte[] c, byte[] rk) {
    //System.out.println("R: " + Arrays.toString(c));
    // c1 \in G1, c2 \in G2
    Field G1 = global.getG1();
    Field G2 = global.getG2();

    Element c1 = G1.newElement();
    int offset = bytesToElement(c, c1, 0);
    c1 = c1.getImmutable();

    Element c2 = G2.newElement();
    bytesToElement(c, c2, offset);
    c2 = c2.getImmutable();

    Tuple t = reEncryption(new Tuple(c1, c2), bytesToElement(rk, G1), global);

    return mergeByteArrays(t.get(1).toBytes(), t.get(2).toBytes());

  }

  public byte[] firstLevelDecryption(byte[] b, byte[] sk) {

    // c1, c2 \in G2
    Field G2 = global.getG2();

    Element alpha = G2.newElement();
    int offset = bytesToElement(b, alpha, 0);
    alpha = alpha.getImmutable();

    Element beta = G2.newElement();
    bytesToElement(b, beta, offset);
    beta = beta.getImmutable();

    Element key = bytesToElement(sk, global.getZq());

    Element m = firstLevelDecryption(new Tuple(alpha, beta), key, global);

    return BigIntUtils.bigIntegerToByteArray(m.toBigInteger());
  }

  private Tuple reEncryption(Tuple c, Element rk,final AFGHGlobalParameters global) {
    /*
     * Re-Encryption
     * c' = ( e(c1, rk) , c2)   \in G2 x G2
     */

    Pairing e = global.getE();

    return new Tuple(e.pairing(c.get(1), rk), c.get(2));

  }

  private Element firstLevelDecryption(Tuple c, Element sk,final AFGHGlobalParameters global) {
    // c1, c2 \in G2
    Element alpha = c.get(1);
    Element beta = c.get(2);

    Element sk_inverse = sk.invert();

    Element m = beta.div(alpha.powZn(sk_inverse));

    return m;
  }

  private int bytesToElement(byte[] b, Element x, int offset) {

    offset += x.setFromBytes(b, offset);

    return offset;
  }

  private byte[] mergeByteArrays(byte[]... bs) {
    int newLength = 0;
    for (byte[] b : bs) {
      newLength += b.length;
    }

    byte[] merge = new byte[newLength];

    int from = 0;
    for (byte[] b : bs) {
      System.arraycopy(b, 0, merge, from, b.length);
      from += b.length;
    }

    return merge;
  }

  public byte[] generatePublicKey(byte[] secretKey) {

    Element skElement = bytesToElement(secretKey, global.getG1());

    ElementPowPreProcessing g = global.getG_ppp();
    // pk = g^sk
    return g.powZn(skElement).getImmutable().toBytes();
  }

  public byte[] generateSecretKey() {
    Field Zq = global.getZq();
    /*
     * KEY GENERATION
     */

    // sk = a \in Zq
    return Zq.newRandomElement().getImmutable().toBytes();
  }

  public AFGHKeyPair generateAFGHKeyPair(){
    AFGHKeyPair afghKeyPair = new AFGHKeyPair();
    afghKeyPair.secretKey = generateSecretKey();
    afghKeyPair.publicKey = generatePublicKey(afghKeyPair.secretKey);
    return afghKeyPair;
  }

}
