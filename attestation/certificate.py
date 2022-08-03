import sys, os.path, argparse, getpass, datetime
from cryptography.hazmat.primitives import hashes, serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.x509.oid import NameOID

# FIDO U2F certificate transports extension
# ASN1.BITSTRING (type 3) format, length 2, 4 unused bits, 3rd bit (= NFC) set (inverse bit order)
fidoTransportExtension = x509.UnrecognizedExtension(
    x509.ObjectIdentifier("1.3.6.1.4.1.45724.2.1.1"), b'\x03\x02\x04\x20')

def create(args):
    # Generate and store private key
    priv_key = ec.generate_private_key(ec.SECP256R1())
    priv_key_der = priv_key.private_bytes(ser.Encoding.DER, ser.PrivateFormat.PKCS8, 
        ser.BestAvailableEncryption(args.privkeypassphrase.encode('utf-8')))
    with open(args.privkeyfile, 'wb') as f: f.write(priv_key_der)
    print('success: Wrote private attestation key file \'' + args.privkeyfile + '\'.')

    # Generate and self-sign certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FlexSecure"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"FlexSecure U2F Token"),
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
        x509.BasicConstraints(ca = False, path_length = None), 
        critical = True
    ).add_extension(
        fidoTransportExtension,
        critical=False
    ).sign(priv_key, hashes.SHA256())

    print('info: Public attestation certificate serial number: ' + str(cert.serial_number))
    fingerprint = cert.fingerprint(hashes.SHA256())
    print('info: Public attestation certificate SHA256 fingerprint: ' + fingerprint.hex())

    # Store certificate
    with open(args.certfile, "wb") as f:
        f.write(cert.public_bytes(ser.Encoding.DER))
    print('success: Wrote public attestation certificate file \'' + args.certfile + '\'.')
