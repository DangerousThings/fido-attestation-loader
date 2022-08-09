import uuid, json
from cryptography.hazmat.primitives import serialization as ser
from cryptography import x509
import asn1
from .certificate import fidoAAGUIDExtensionOID, cert_print_info
from .loader import generate_apdus


def show_cert(args, conf):
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
    _, priv_key_bytes = decoder.read() # privateKey

    # Construct installation parameter
    cert = x509.load_der_x509_certificate(cert_der)
    flags = '00'
    if(args.mode == 'u2fci'): flags = '01'
    param = flags + f'{len(cert_der):04x}' + priv_key_bytes.hex()
    if(args.mode == 'fido2'):
        decoder = asn1.Decoder()
        decoder.start(cert.extensions.get_extension_for_oid(fidoAAGUIDExtensionOID).value.value)
        _, aaguid_bytes = decoder.read()
        param += aaguid_bytes.hex()

    # Print public cert and some preamble
    if(args.format == 'human'):
        cert_print_info(cert, 'attestation certificate')
        print('info: Public attestation certificate (' + str(len(cert_der))  + ' bytes): ' + cert_der.hex())
        print('info: Private attestation key (32 bytes): ' + priv_key_bytes.hex())
        if(args.mode == 'u2f' or args.mode == 'u2fci'):
            print('info: Applet installation parameter (contains private attestation key 32 bytes):')
        elif(args.mode == 'fido2'):
            print('info: AAGUID: ' + str(uuid.UUID(bytes=aaguid_bytes)))
            print('info: Applet installation parameter (contains private attestation key 32 bytes, AAGUID 16 bytes):')
    
    # Print installation parameter
    if(args.format == 'human' or args.format == 'parameter'):
        print(param)
    elif(args.format == 'fidesmo'):
        apdus = generate_apdus(cert_der, args)
        js = {
            "description": {
                "title": conf.fidesmo.title,
                "description": str.encode(conf.fidesmo.description).decode('unicode_escape'), # Handles \r and \n
                "requirements": {
                    "issuerAccountId": conf.fidesmo.issuerAccountId
                }
            },
            "confirmationRequired": False,
            "actions": [
                {
                    "endpoint": "/ccm/install",
                    "content": {
                        "executableLoadFile": conf.fidesmo.executableLoadFile,
                        "executableModule": conf.fidesmo.executableModule,
                        "application": conf.fidesmo.application,
                        "parameters": param
                    }
                },
                {
                    "endpoint": "/transceive",
                    "content": {
                        "commands": [bytes(x).hex() for x in apdus],
                        "waitingMessage": conf.fidesmo.waitingMessage
                    }
                }
            ],
            "successMessage": conf.fidesmo.successMessage,
            "failureMessage": conf.fidesmo.failureMessage
        }
        serialized = json.dumps(js, sort_keys=False, indent=2)
        print(serialized)
