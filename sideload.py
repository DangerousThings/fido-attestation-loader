#!/usr/bin/env python3

import sys, os.path
import argparse, getpass
import asn1
from cryptography.hazmat.primitives import serialization as ser

# Load and decrypt private key
passphrase = getpass.getpass('PROMPT: Enter passphrase for private key: ')
with open('attestation_key.p8', 'rb') as f:
    try:
        priv_key_der = ser.load_der_private_key(f.read(), password = passphrase.encode('utf-8')).private_bytes(
            ser.Encoding.DER, ser.PrivateFormat.TraditionalOpenSSL, ser.NoEncryption())
    except ValueError as e:
        print('ERROR: Cannot read private key: ' + str(e))
        exit(1)

# Extract the DER / ASN1 PKCS#1 encoded private key bytes
decoder = asn1.Decoder()
decoder.start(priv_key_der)
decoder.enter() # SEQUENCE
decoder.read() # ecPrivkeyVer1
tag, priv_key_bytes = decoder.read() # privateKey
print("Private key bytes: " + priv_key_bytes.hex())
