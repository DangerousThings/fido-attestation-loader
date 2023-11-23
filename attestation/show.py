import uuid, json, base64, cbor2
from cryptography.hazmat.primitives import hashes, serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
import asn1
from .certificate import fidoAAGUIDExtensionOID, cert_print_info, cert_public_bytes_der, key_private_bytes_der
from .loader import generate_apdus


def show_cert(args, conf):
    with open(args.certfile, 'rb') as f:
        cert_der = f.read()
    with open(args.privkeyfile, 'rb') as f:
        try:
            priv_key = ser.load_der_private_key(f.read(), password = args.privkeypassphrase.encode('utf-8'))
        except ValueError as e:
            print('error: Cannot read private attestation certificate key: ' + str(e))
            exit(1)
    with open(args.cacertfile, 'rb') as f:
        ca_der = f.read()

    # Construct installation parameter
    ca = x509.load_der_x509_certificate(ca_der)
    cert = x509.load_der_x509_certificate(cert_der)
    priv_key_bytes = key_private_bytes_der(priv_key)
    if(args.mode != 'fido21'):
        flags = '00'
        if(args.mode == 'u2fci'): 
            flags = '01'
        if(args.mode == 'fido2ci'): 
            flags = '03'
        param = flags + f'{len(cert_der):04x}' + priv_key_bytes.hex()
    else:
        param = cbor2.dumps({
            0: True, # enable_attestation
            4: True, # protect_against_reset
            5: 5, # kdf_iterations
            6: 32, # max_cred_blob_len
            7: 1024, # large_blob_store_size
            8: 32, # max_rk_rp_length
            9: 254, # max_ram_scratch
            10: 1024, # buffer_mem
            11: 1024, # flash_scratch
            15: priv_key_bytes # attestation_private_key
        }).hex()

    decoder = asn1.Decoder()
    decoder.start(cert.extensions.get_extension_for_oid(fidoAAGUIDExtensionOID).value.value)
    _, aaguid_bytes = decoder.read()
    if(args.mode == 'fido2' or args.mode == 'fido2ci'):
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
            print('info: Applet installation parameter (contains header 3 bytes, private attestation key 32 bytes):')
        elif(args.mode == 'fido2' or args.mode == 'fido2ci'):
            print('info: Applet installation parameter (contains header 3 bytes, private attestation key 32 bytes, AAGUID 16 bytes):')
        elif(args.mode == 'fido21' or args.mode == 'fido2ci'):
            print('info: Applet installation parameter (contains CBOR configuration map with private attestation key 32 bytes):')
    
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
            'legalHeader': 'https:#fidoalliance.org/metadata/metadata-statement-legal-header/',
            'description': conf.meta.description,
            'authenticatorVersion': 1,
            'protocolFamily': 'fido2' if (args.mode == 'fido2' or args.mode == 'fido2ci' or args.mode == 'fido21') else 'u2f',
            'schema': 3,
            'authenticationAlgorithms': [
                'secp256r1_ecdsa_sha256_raw' if (args.mode != 'fido21') else 'secp256r1_ecdsa_sha256_der'
            ],
            'publicKeyAlgAndEncodings': [
                'cose' if (args.mode == 'fido2' or args.mode == 'fido2ci' or args.mode == 'fido21') else 'ecc_x962_raw'
            ],
            'attestationTypes': [
                'basic_full'
            ],
            'userVerificationDetails': [
                [
                    {
                        'userVerificationMethod': 'none'
                    }
                ],
                [
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
            'isFreshUserVerificationRequired': True,
            'tcDisplay': [ ],
            "supportedExtensions": [ ],
            'attestationRootCertificates': [
                base64.b64encode(ca_der).decode('ASCII')
            ],
            'icon': conf.meta.icon
        }
        if(args.mode == 'u2f' or args.mode == 'u2fci'):
            js['upv'] = [
                {
                    'major': 1,
                    'minor': 2
                }
            ]
            js['attestationCertificateKeyIdentifiers'] = [
                (x509.SubjectKeyIdentifier.from_public_key(cert.public_key())).digest.hex()
            ]
        elif(args.mode == 'fido2' or args.mode == 'fido2ci' or args.mode == 'fido21'):
            js['upv'] = [
                {
                    'major': 1,
                    'minor': 0
                }
            ]
            if(args.mode == 'fido21'):
                js['upv'] += [
                {
                    'major': 1,
                    'minor': 1
                }
            ]
            js['aaguid'] = aaguid
            js['userVerificationDetails'] += [
                [
                    {
                        'userVerificationMethod': 'passcode_external',
                        'caDesc': { 
                            'base': 10,
                            'minLength': 4,
                            'maxRetries': 8
                        }
                    }
                ],
                [
                    {
                        'userVerificationMethod': 'passcode_external',
                        'caDesc': { 
                            'base': 10,
                            'minLength': 4,
                            'maxRetries': 8
                        }
                    },
                    {
                        'userVerificationMethod': 'presence_internal'
                    }
                ]
            ]
            if(args.mode == 'fido2' or args.mode == 'fido2ci'):
                js['authenticationAlgorithms'] += [
                    'rsassa_pkcsv15_sha256_raw',
                    'rsassa_pss_sha256_raw'
                ]
            js['authenticatorGetInfo'] = {}
        serialized = json.dumps(js, sort_keys=False, indent=2)
        print(serialized)
