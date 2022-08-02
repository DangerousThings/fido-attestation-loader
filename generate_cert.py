#!/usr/bin/env python3

import sys, os.path
import argparse, getpass
import asn1
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec

# Parse CLI arguments
parser = argparse.ArgumentParser(description = 'Generate a x509 FIDO attestation certificate')
parser.add_argument('-c --certificate', nargs='?', dest='certfile', type=str, 
    const='attestation.der', default='attestation.der', 
    help='filename of the generated public certificate (default: attestation.der)')
parser.add_argument('-k --private-key', nargs='?', dest='privkeyfile', type=str, 
    const='attestation_key.p8', default='attestation_key.p8', 
    help='filename of the generated private key (default: attestation_key.p8)')
parser.add_argument('-p --private-key-passphrase', nargs='?', dest='privkeypassphrase', type=str,
    help='passphrase to encrypt the generated private key')
parser.add_argument('-o --overwrite', dest='overwrite', type=bool, 
    default=False, action = argparse.BooleanOptionalAction,
    help='allow overwriting existing files')
group_sign = parser.add_mutually_exclusive_group()
group_sign.add_argument('-s --self-sign', dest='selfsign',
    action='store_true', help='generate a self-signed certificate')
group_sign.add_argument('-a --authority-sign', dest='selfsign',
     action='store_false', help='sign certificate using certificate authority')
parser.add_argument('-ca --certificate-authority', nargs='?', dest='cafile', type=str, 
    const='ca.crt', default='ca.crt', 
    help='filename of the certificate authority (default: ca.crt)')
args = parser.parse_args()

# Check private key CLI arguments
if(os.path.isfile(args.privkeyfile) and (not args.overwrite)):
    print('ERROR: Private key file \'' + args.privkeyfile + 
        '\' already exists. Run with \'-o\' to enable overwriting files.')
    exit(1)
if(args.privkeypassphrase is None):
    pw1 = getpass.getpass('PROMPT: No passphrase to encrypt the private key specified, please create one: ')
    pw2 = getpass.getpass('PROMPT: Re-type passphrase for confirmation: ')
    if(pw1 == pw2):
        args.privkeypassphrase = pw1
    else:
        print('ERROR: Passphrases do not match.')
        exit(1)

# Generate and store private key
priv_key = ec.generate_private_key(ec.SECP256R1())
priv_key_der = priv_key.private_bytes(ser.Encoding.DER, ser.PrivateFormat.PKCS8, 
    ser.BestAvailableEncryption(args.privkeypassphrase.encode('utf-8')))
with open(args.privkeyfile, 'wb') as f: f.write(priv_key_der)
print('SUCCESS: Wrote private key file \'' + args.privkeyfile + '\'.')

# Generate certificate
priv_key_der2 = priv_key.private_bytes(ser.Encoding.DER, ser.PrivateFormat.TraditionalOpenSSL, 
    ser.NoEncryption())
decoder = asn1.Decoder()
decoder.start(priv_key_der2)
decoder.enter() # SEQUENCE
decoder.read() # ecPrivkeyVer1
tag, priv_key_bytes = decoder.read() # privateKey
print("Private key bytes: " + priv_key_bytes.hex())


# Sign certificate
# if(not args.selfsign):
#    if(not os.path.isfile(args.cafile)):
#        print('ERROR: Certificate authority file \'' + args.cafile + '\' does not exist.')
#        exit(1)
