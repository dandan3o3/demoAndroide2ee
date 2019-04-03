package com.tsystems.e2ee.crypto.afgh;

import androidx.annotation.Nullable;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.util.StringTokenizer;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.ElementPowPreProcessing;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.jpbc.PairingParametersGenerator;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveField;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;

/*
 * Copyright (c) 2018 T-Systems Multimedia Solutions GmbH
 * Riesaer Str. 5, D-01129 Dresden, Germany
 * All rights reserved.
 *
 * Autor: yuti
 * Datum: 24/10/2018
 */
public class AFGHCryptoParameters {

  private final int rBits = 256;
  private final int qBits = 1536;
  private final boolean generateCurveFieldGen = false;

  ///
  private Pairing e;
  private Field G1, G2, Zq;
  private Element g, Z;
  private ElementPowPreProcessing g_ppp, Z_ppp;

  private PairingParameters curveParams;
  private String afghInitParametersString;

  public AFGHCryptoParameters(@Nullable PairingParameters curveParams) {
    if (curveParams == null) {
      this.curveParams = generatePairingParameters();
    }else {
      this.curveParams = curveParams;
    }
    this.afghInitParametersString = curveParams.toString();

    initialPairing();
  }


  public ElementPowPreProcessing getZ_ppp() {
    return Z_ppp;
  }

  public void setZ_ppp(ElementPowPreProcessing z_ppp) {
    Z_ppp = z_ppp;
  }

  public AFGHCryptoParameters(@Nullable String cryptoParametersInitalString) {
    if (cryptoParametersInitalString == null) {
      this.curveParams = generatePairingParameters();
      this.afghInitParametersString = curveParams.toString();
    }else {
      this.afghInitParametersString = cryptoParametersInitalString;
      PropertiesParameters propertiesParameters = new PropertiesParameters();
      readFromString(cryptoParametersInitalString,propertiesParameters);
      this.curveParams = propertiesParameters;
    }

    initialPairing();
  }

  public String toCryptoParametersInitalString(){
    return this.curveParams.toString();
  }

  private PairingParameters generatePairingParameters() {

    // Init the generator...
    PairingParametersGenerator curveGenerator = new TypeACurveGenerator(rBits, qBits, generateCurveFieldGen);

    // Generate the parameters...
    return curveGenerator.generate();
  }

  private void initialPairing() {

    e = PairingFactory.getPairing(curveParams);

    // Groups G1 and G2 of prime order q
    G1 = e.getG1();
    G2 = e.getGT();

    // Field Zq
    Zq = e.getZr();

    // Global system parameters: g \in G1, Z = e(g,g) \in G2
    g = ((CurveField) G1).getGen().getImmutable();

    Z = e.pairing(g, g).getImmutable();

    Z_ppp = Z.getElementPowPreProcessing();
    g_ppp = g.getElementPowPreProcessing();

  }

  public Pairing getE() {
    return e;
  }

  public Field getG1() {
    return G1;
  }

  public Field getG2() {
    return G2;
  }

  public Field getZq() {
    return Zq;
  }

  public Element getG() {
    return g;
  }

  public Element getZ() {
    return Z;
  }

  public ElementPowPreProcessing getG_ppp() {
    return g_ppp;
  }

  public PairingParameters getCurveParams() {
    return curveParams;
  }

  // use to share AFGHGlobalParameters across the all the participant party
  public void readFromString(String inputString, final PropertiesParameters propertiesParameters){
    Reader inputStringReader = new StringReader(inputString);
    BufferedReader reader = new BufferedReader(inputStringReader);

    try {
      while(true) {
        String line = reader.readLine();
        if(line == null) {
          return;
        }

        line = line.trim();
        if(line.length() != 0 && !line.startsWith("#")) {
          StringTokenizer tokenizer = new StringTokenizer(line, "= :", false);
          String key = tokenizer.nextToken();
          String value = tokenizer.nextToken();
          propertiesParameters.put(key, value);
        }
      }

    } catch (IOException var7) {
      throw new RuntimeException(var7);
    }

  }
}
