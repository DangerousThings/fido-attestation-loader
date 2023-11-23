import datetime
from cryptography.hazmat.primitives import hashes, serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.exceptions import InvalidSignature
import asn1


# FIDO U2F certificate transports extension
# ASN1.BITSTRING (type 3) format, length 2, 4 unused bits, 3rd bit (= NFC) set (inverse bit order)
fidoTransportExtension = x509.UnrecognizedExtension(
    x509.ObjectIdentifier('1.3.6.1.4.1.45724.2.1.1'), b'\x03\x02\x04\x10')

# FIDO2 AAGUID extension
fidoAAGUIDExtensionOID = x509.ObjectIdentifier('1.3.6.1.4.1.45724.1.1.4')


def __create_private_key(passphrase, curve, name, file):
    # Generate and store private key
    priv_key = ec.generate_private_key(curve)
    priv_key_der = priv_key.private_bytes(ser.Encoding.DER, ser.PrivateFormat.PKCS8, 
        ser.BestAvailableEncryption(passphrase.encode('utf-8')))
    with open(file, 'wb') as f: f.write(priv_key_der)
    print('success: Wrote private ' + name + ' key file \'' + file + '\'')
    return priv_key


def __store_public(cert, file, name):
    cert_print_info(cert, name)
    with open(file, 'wb') as f:
        f.write(cert.public_bytes(ser.Encoding.DER))
    print('success: Wrote public ' + name + ' file \'' + file + '\'')


def cert_public_bytes_der(cert):
    der_fragment = cert.public_key().public_bytes(
        ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)
    # Extract the DER / ASN1 PKCS#1 encoded public key bytes
    decoder = asn1.Decoder()
    decoder.start(der_fragment)
    decoder.enter() # SEQUENCE
    decoder.read() # skip algorithm identifier
    _, pub_key_bytes = decoder.read() # publicKey
    return pub_key_bytes


def key_private_bytes_der(priv_key):
    der_fragment = priv_key.private_bytes(
        ser.Encoding.DER, ser.PrivateFormat.TraditionalOpenSSL, ser.NoEncryption())
    # Extract the DER / ASN1 PKCS#1 encoded private key bytes
    decoder = asn1.Decoder()
    decoder.start(der_fragment)
    decoder.enter() # SEQUENCE
    decoder.read() # ecPrivkeyVer1
    _, priv_key_bytes = decoder.read() # privateKey
    return priv_key_bytes


def cert_print_info(cert, name):
    print('info: Public ' + name + ' serial number: ' + str(cert.serial_number))
    fingerprint = cert.fingerprint(hashes.SHA256())
    print('info: Public ' + name + ' SHA256 fingerprint: ' + fingerprint.hex())


def create_ca(args, conf):
    priv_key = __create_private_key(args.caprivkeypassphrase, 
        ec.SECP256R1(), 'certificate authority', args.caprivkeyfile)

    # Self-sign CA
    subject = issuer = conf.caName
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
        x509.BasicConstraints(ca = True, path_length = 0), critical = True
    ).add_extension(
        x509.KeyUsage(key_cert_sign = True, crl_sign = True,
            digital_signature = False, content_commitment = False, 
            key_encipherment = False, data_encipherment = False, 
            key_agreement = False, encipher_only = False, decipher_only = False),
        critical = True
    ).sign(priv_key, hashes.SHA256())

    __store_public(cert, args.cacertfile, 'certificate authority')


def create_cert(args, conf):
    curve = ec.SECP256R1()
    priv_key_cert = __create_private_key(args.privkeypassphrase, 
        curve, 'attestation certificate', args.privkeyfile)

    # Generate CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        conf.certName).sign(priv_key_cert, hashes.SHA256())

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
        x509.BasicConstraints(ca = False, path_length = None), critical = True
    ).add_extension(
        fidoTransportExtension, critical = False
    ).add_extension(
        conf.fido2.oidExt, critical = False
    ).add_extension(
        conf.fido2.aaguidExt, critical = False)

    cert = cert.sign(priv_key_ca, hashes.SHA256())
    cert_print_info(ca, 'certificate authority')
    __store_public(cert, args.certfile, 'attestation certificate')


def validate_cert(args):
    with open(args.certfile, 'rb') as f:
        cert = x509.load_der_x509_certificate(f.read())
    cert_print_info(cert, 'attestation certificate')
    with open(args.cacertfile, 'rb') as f:
        ca = x509.load_der_x509_certificate(f.read())
    cert_print_info(ca, 'certificate authority')

    try:
        # Use ECDSA for verifying
        ca.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
        print('success: The attestation certificate has a valid signature by the certificate authority')
    except InvalidSignature as e:
        print('error: the attestation certificate does not have a valid signature by the certificate authority')
        exit(1)
