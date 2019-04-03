package com.tsystems.e2ee.crypto;

import java.math.BigInteger;
import java.util.Arrays;

public class BigIntUtils {
  public static byte[] bigIntegerToByteArray(BigInteger value) {
    byte[] valueBytes = value.toByteArray();
    if (value.bitLength() % 8 == 0 && valueBytes.length > value.bitLength()/8) {
      int offset = valueBytes.length - value.bitLength()/8;
      /* we have a redundant leading zero byte (due to the implementation of BigInteger and must remove it */
      return Arrays.copyOfRange(value.toByteArray(), offset, valueBytes.length);
    } else {
      return valueBytes;
    }
  }
}
