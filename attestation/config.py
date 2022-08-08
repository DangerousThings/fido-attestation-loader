import os, configparser, uuid
from typing import NamedTuple
from cryptography import x509
from cryptography.x509.oid import NameOID
import asn1
from .certificate import fidoAAGUIDExtensionOID


class AttConfig(NamedTuple):
    caName: x509.Name
    certName: x509.Name
    fido2AAGUID: uuid.UUID
    fido2AAGUIDExt: x509.ExtensionType
    fido2OIDExt: x509.ExtensionType


def parse(file):
    if(os.path.isfile(file)):
        print('info: Loading settings file ' + file)
    else:
        print('info: Using default settings')
    config = configparser.ConfigParser()
    config.read(file)

    aaguid = uuid.UUID(config.get('fido2', 'aaguid', fallback='27291256-2735-45b5-99f9-2863c9dddd72'))
    encoder = asn1.Encoder()
    encoder.start()
    encoder.write(aaguid.bytes, asn1.Numbers.OctetString)
    aaguid_bin = encoder.output()

    return AttConfig(
        caName = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, config.get('ca', 'O', fallback='Attestation')),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, config.get('ca', 'OU', fallback='Authenticator Attestation')),
            x509.NameAttribute(NameOID.COMMON_NAME, config.get('ca', 'CN', fallback='Attestation Root CA'))
        ]),
        certName = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, config.get('cert', 'O', fallback='Attestation')),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, config.get('cert', 'OU', fallback='Authenticator Attestation')),
            x509.NameAttribute(NameOID.COMMON_NAME, config.get('cert', 'CN', fallback='Attestation Token'))
        ]),
        fido2AAGUID = aaguid,
        fido2AAGUIDExt = x509.UnrecognizedExtension(fidoAAGUIDExtensionOID, aaguid_bin),
        fido2OIDExt = x509.UnrecognizedExtension(x509.ObjectIdentifier(config.get('fido2', 'devns', fallback='1.3.6.1.4.1.0.2')), 
            config.get('fido2', 'devid', fallback='1.3.6.1.4.1.0.1.1').encode('ASCII')))
