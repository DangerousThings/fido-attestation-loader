import sys, os.path, argparse, getpass, datetime
from cryptography.hazmat.primitives import hashes, serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.exceptions import InvalidSignature
import asn1

# FIDO U2F certificate transports extension
# ASN1.BITSTRING (type 3) format, length 2, 4 unused bits, 3rd bit (= NFC) set (inverse bit order)
fidoTransportExtension = x509.UnrecognizedExtension(
    x509.ObjectIdentifier('1.3.6.1.4.1.45724.2.1.1'), b'\x03\x02\x04\x20')

def __create_private_key(passphrase, curve, file):
    # Generate and store private key
    priv_key = ec.generate_private_key(curve)
    priv_key_der = priv_key.private_bytes(ser.Encoding.DER, ser.PrivateFormat.PKCS8, 
        ser.BestAvailableEncryption(passphrase.encode('utf-8')))
    with open(file, 'wb') as f: f.write(priv_key_der)
    print('success: Wrote private certificate authority key file \'' + file + '\'.')
    return priv_key

def __print_info(cert, name):
    print('info: Public ' + name + ' serial number: ' + str(cert.serial_number))
    fingerprint = cert.fingerprint(hashes.SHA256())
    print('info: Public ' + name + ' SHA256 fingerprint: ' + fingerprint.hex())

def __store_public(cert, file, name):
    __print_info(cert, name)
    with open(file, 'wb') as f:
        f.write(cert.public_bytes(ser.Encoding.DER))
    print('success: Wrote public attestation certificate file \'' + file + '\'.')

def create_ca(args):
    priv_key = __create_private_key(args.caprivkeypassphrase, 
        ec.SECP384R1(), args.caprivkeyfile)

    # Self-sign CA
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'FlexSecure'),
        x509.NameAttribute(NameOID.COMMON_NAME, u'FlexSecure U2F Root CA'),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        priv_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days = args.days)
    ).add_extension(
        x509.BasicConstraints(ca = True, path_length = 0), 
        critical = True
    ).add_extension(
        x509.KeyUsage(key_cert_sign = True, crl_sign = True,
            digital_signature = False, content_commitment = False, 
            key_encipherment = False, data_encipherment = False, 
            key_agreement = False, encipher_only = False, decipher_only = False),
        critical = True
    ).sign(priv_key, hashes.SHA256())

    __store_public(cert, args.cacertfile, 'certificate authority')


def create_cert(args):
    priv_key_cert = __create_private_key(args.privkeypassphrase, 
        ec.SECP256R1(), args.privkeyfile)

    # Generate CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'FlexSecure'),
            x509.NameAttribute(NameOID.COMMON_NAME, u'FlexSecure U2F Token'),
        ])
    ).sign(priv_key_cert, hashes.SHA256())

    # Load CA
    with open(args.cacertfile, 'rb') as f:
        ca = x509.load_der_x509_certificate(f.read())
    with open(args.caprivkeyfile, 'rb') as f:
        try:
            priv_key_ca = ser.load_der_private_key(f.read(), password = args.caprivkeypassphrase.encode('utf-8'))
        except ValueError as e:
            print('error: Cannot read private certificate authority key: ' + str(e))
            exit(1)

    # Generate and sign cert
    cert = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        ca.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days = args.days)
    ).add_extension(
        x509.BasicConstraints(ca = False, path_length = None), 
        critical = True
    ).add_extension(
        x509.KeyUsage(digital_signature = True, key_encipherment = True, content_commitment = True,
            data_encipherment = False, key_agreement = False, 
            key_cert_sign = False, crl_sign = False, 
            encipher_only = False, decipher_only = False),
        critical = True
    ).add_extension(
        x509.ExtendedKeyUsage([ ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH, 
            ExtendedKeyUsageOID.CODE_SIGNING, ExtendedKeyUsageOID.EMAIL_PROTECTION ]),
        critical = True
    ).add_extension(
        fidoTransportExtension,
        critical = False
    ).sign(priv_key_ca, hashes.SHA256())

    __print_info(ca, 'certificate authority')
    __store_public(cert, args.certfile, 'attestation certificate')

def show_cert(args):
    with open(args.certfile, 'rb') as f:
        cert_der = f.read()
    with open(args.privkeyfile, 'rb') as f:
        try:
            priv_key_der = ser.load_der_private_key(f.read(), 
                password = args.privkeypassphrase.encode('utf-8')).private_bytes(
                    ser.Encoding.DER, ser.PrivateFormat.TraditionalOpenSSL, ser.NoEncryption())
        except ValueError as e:
            print('error: Cannot read private attestation certificate key: ' + str(e))
            exit(1)

    # Extract the DER / ASN1 PKCS#1 encoded private key bytes
    decoder = asn1.Decoder()
    decoder.start(priv_key_der)
    decoder.enter() # SEQUENCE
    decoder.read() # ecPrivkeyVer1
    tag, priv_key_bytes = decoder.read() # privateKey

    __print_info(x509.load_der_x509_certificate(cert_der), 'attestation certificate')
    print('info: Public attestation certificate bytes (length = 0x' + f'{len(cert_der):x}' + '):')
    print(cert_der.hex())
    print('info: Private attestation key bytes (length = 0x' + f'{len(priv_key_bytes):x}' + '):')
    print(priv_key_bytes.hex())

def validate_cert(args):
    with open(args.certfile, 'rb') as f:
        cert = x509.load_der_x509_certificate(f.read())
    __print_info(cert, 'attestation certificate')
    with open(args.cacertfile, 'rb') as f:
        ca = x509.load_der_x509_certificate(f.read())
    __print_info(ca, 'certificate authority')

    try:
        ca.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
        print('success: The attestation certificate has a valid signature by the certificate authority')
    except InvalidSignature as e:
        print('error: the attestation certificate does not have a valid signature by the certificate authority')
        exit(1)
