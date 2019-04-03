#!/bin/bash

ALIAS=$1
NAME=$2

ALIAS1=${ALIAS}_enc
ALIAS2=${ALIAS}_sig

openssl req -config openssl.conf \
  -newkey rsa:2048 -keyout private/$ALIAS1.key.pem.enc \
  -passout "pass:changeit" \
  -new -sha256 -out csr/$ALIAS1.csr \
  -subj "/C=DE/ST=Germany/O=T-Systems MMS/OU=E2EE development/CN=$NAME/CN=encryption"

openssl rsa -in private/$ALIAS1.key.pem.enc -out private/$ALIAS1.key.pem -passin "pass:changeit"
rm private/$ALIAS1.key.pem.enc
chmod 400 private/$ALIAS1.key.pem

openssl ca -config openssl.conf \
  -extensions server_cert -days 375 -notext -md sha256 \
  -in csr/$ALIAS1.csr -out certs/$ALIAS1.cert.pem \
  -batch

chmod 444 certs/$ALIAS1.cert.pem

openssl req -config openssl.conf \
  -newkey rsa:2048 -keyout private/$ALIAS2.key.pem.enc \
  -passout "pass:changeit" \
  -new -sha256 -out csr/$ALIAS2.csr \
  -subj "/C=DE/ST=Germany/O=T-Systems MMS/OU=E2EE development/CN=$NAME/CN=signature"

openssl rsa -in private/$ALIAS2.key.pem.enc -out private/$ALIAS2.key.pem -passin "pass:changeit"
rm private/$ALIAS2.key.pem.enc
chmod 400 private/$ALIAS2.key.pem

openssl ca -config openssl.conf \
  -extensions server_cert -days 375 -notext -md sha256 \
  -in csr/$ALIAS2.csr -out certs/$ALIAS2.cert.pem \
  -batch

chmod 444 certs/$ALIAS2.cert.pem

# create PKCS#12 files
openssl pkcs12 -export -out private/$ALIAS1.pfx -inkey private/$ALIAS1.key.pem -in certs/$ALIAS1.cert.pem -name $ALIAS1 -passout "pass:changeit" -chain -CAfile certs/ca-chain.cert.pem
openssl pkcs12 -export -out private/$ALIAS2.pfx -inkey private/$ALIAS2.key.pem -in certs/$ALIAS2.cert.pem -name $ALIAS2 -passout "pass:changeit" -chain -CAfile certs/ca-chain.cert.pem

