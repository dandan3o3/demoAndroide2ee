/*
 * Copyright (c) 2017 T-Systems
 * All rights reserved.
 *
 * Name: CryptographyException.java
 * Autor: Jan Starke (jasa)
 * Datum: 03.07.2017
 */
package com.tsystems.e2ee.crypto;

/**
 * General Exception for problems relating cryptography
 *
 * @author Jan Starke (jasa)
 * @version 1.0
 */
public class CryptographyException extends Exception {

  /**
   * Calls the super constructor with error message.
   *
   * @param errorMessage
   *          - Error message.
   */
  public CryptographyException(String errorMessage) {
    super(errorMessage);
  }

  /**
   * Calls super with error message and a cause.
   *
   * @param errorMessage
   *          - Error message.
   * @param cause
   *          - Error cause.
   */
  public CryptographyException(String errorMessage, Exception cause) {
    super(errorMessage, cause);
  }
}