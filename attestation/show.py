import uuid, json, base64
from cryptography.hazmat.primitives import serialization as ser
from cryptography import x509
import asn1
from .certificate import fidoAAGUIDExtensionOID, cert_print_info
from .loader import generate_apdus


def show_cert(args, conf):
    with open(args.certfile, 'rb') as f:
        cert_der = f.read()
    with open(args.cacertfile, 'rb') as f:
        ca_der = f.read()
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
    ca = x509.load_der_x509_certificate(ca_der)
    cert = x509.load_der_x509_certificate(cert_der)
    flags = '00'
    if(args.mode == 'u2fci'): flags = '01'
    param = flags + f'{len(cert_der):04x}' + priv_key_bytes.hex()
    decoder = asn1.Decoder()
    decoder.start(cert.extensions.get_extension_for_oid(fidoAAGUIDExtensionOID).value.value)
    _, aaguid_bytes = decoder.read()
    if(args.mode == 'fido2'):
        param += aaguid_bytes.hex()
    aaguid = str(uuid.UUID(bytes=aaguid_bytes))

    # Print public cert and some preamble
    if(args.format == 'human'):
        cert_print_info(ca, 'certificate authority')
        cert_print_info(cert, 'attestation certificate')
        print('info: Public attestation certificate (' + str(len(cert_der))  + ' bytes): ' + cert_der.hex())
        print('info: Private attestation key (32 bytes): ' + priv_key_bytes.hex())
        print('info: AAGUID: ' + aaguid)
        if(args.mode == 'u2f' or args.mode == 'u2fci'):
            print('info: Applet installation parameter (contains private attestation key 32 bytes):')
        elif(args.mode == 'fido2'):
            print('info: Applet installation parameter (contains private attestation key 32 bytes, AAGUID 16 bytes):')
    
    # Print installation parameter
    if(args.format == 'human' or args.format == 'parameter'):
        print(param)
    elif(args.format == 'fidesmo'):
        apdus = generate_apdus(cert_der, args)
        js = {
            'description': {
                'title': conf.fidesmo.title,
                'description': str.encode(conf.fidesmo.description).decode('unicode_escape'), # Handles \r and \n
                'requirements': {
                    'issuerAccountId': conf.fidesmo.issuerAccountId
                }
            },
            'confirmationRequired': False,
            'actions': [
                {
                    'endpoint': '/ccm/install',
                    'content': {
                        'executableLoadFile': conf.fidesmo.executableLoadFile,
                        'searchBy': conf.fidesmo.searchBy,
                        'executableModule': conf.fidesmo.executableModule,
                        'application': conf.fidesmo.application,
                        'parameters': param
                    }
                },
                {
                    'endpoint': '/transceive',
                    'content': {
                        'commands': [bytes(x).hex() for x in apdus],
                        'waitingMessage': conf.fidesmo.waitingMessage
                    }
                }
            ],
            'successMessage': conf.fidesmo.successMessage,
            'failureMessage': conf.fidesmo.failureMessage
        }
        serialized = json.dumps(js, sort_keys=False, indent=2)
        print(serialized)
    elif(args.format == 'metadata'):
        js = {
            'legalHeader': 'https://fidoalliance.org/metadata/metadata-statement-legal-header/',
            'aaguid': aaguid,
            'attestationCertificateKeyIdentifiers': [
                (x509.SubjectKeyIdentifier.from_public_key(cert.public_key())).digest.hex()
            ],
            'description': conf.meta.description,
            'authenticatorVersion': 1,
            'protocolFamily': 'fido2' if (args.mode == 'fido2') else 'u2f',
            'schema': 3,
            'upv': [
                {
                    'major': 1,
                    'minor': 0
                }
            ],
            'authenticationAlgorithms': [
                'secp256r1_ecdsa_sha256_raw'
            ],
            'publicKeyAlgAndEncodings': [
                'cose' if (args.mode == 'fido2') else 'ecc_x962_raw'
            ],
            'attestationTypes': [
                'basic_full'
            ],
            'userVerificationDetails': [
                [
                    {
                        'userVerificationMethod': 'none'
                    },
                    {
                        'userVerificationMethod': 'presence_internal'
                    }
                ]
            ],
            'keyProtection': [
                'hardware',
                'secure_element'
            ],
            'matcherProtection': [
                'on_chip'
            ],
            'cryptoStrength': 128,
            'attachmentHint': [
                'external',
                'wireless',
                'nfc'
            ],
            'attestationRootCertificates': [
                base64.b64encode(ca_der).decode('ASCII')
            ],
            'icon': conf.meta.icon
        }
        if(args.mode == 'fido2'):
            js['authenticatorGetInfo'] = {
                'versions': [ 'FIDO_2_0' ],
                'extensions': [ ],
                'aaguid': aaguid_bytes.hex(),
                'options': {
                    'rk': True,
                    'up': True,
                    'uv': True,
                },
                'maxMsgSize': 1200,
                'transports': [ 'nfc' ],
                'algorithms': [
                    {
                        'type': 'public-key',
                        'alg': -7
                    }
                ]
            }
        serialized = json.dumps(js, sort_keys=False, indent=2)
        print(serialized)
