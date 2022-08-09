import os, configparser, uuid, base64
from typing import NamedTuple
from cryptography import x509
from cryptography.x509.oid import NameOID
import asn1
from .certificate import fidoAAGUIDExtensionOID


class MetaConfig(NamedTuple):
    description: str
    icon: str

class FIDO2Config(NamedTuple):
    aaguid: uuid.UUID
    aaguidExt: x509.ExtensionType
    oidExt: x509.ExtensionType

class FidesmoConfig(NamedTuple):
    title: str
    description: str
    issuerAccountId: int
    executableLoadFile: str
    executableModule: str
    application: str
    waitingMessage: str
    successMessage: str
    failureMessage: str

class AttConfig(NamedTuple):
    meta: MetaConfig
    caName: x509.Name
    certName: x509.Name
    fido2: FIDO2Config
    fidesmo: FidesmoConfig


def _encode_icon(iconfile):
    with open(iconfile, 'rb') as f:
        png_bytes = f.read()
    return 'data:image/png;base64,' + base64.b64encode(png_bytes).decode('ASCII')


def parse(args):
    if(args.verb != 'show' or args.format == 'human'):
        if(os.path.isfile(args.settings)):
            print('info: Loading settings file ' + args.settings)
        else:
            print('info: Using default settings')
    config = configparser.ConfigParser()
    config.read(args.settings)

    aaguid = uuid.UUID(config.get('fido2', 'aaguid', fallback='27291256-2735-45b5-99f9-2863c9dddd72'))
    encoder = asn1.Encoder()
    encoder.start()
    encoder.write(aaguid.bytes, asn1.Numbers.OctetString)
    aaguid_bin = encoder.output()

    return AttConfig(
        meta = MetaConfig(
            description = config.get('metadata', 'description', fallback='Generic FIDO Token'),
            icon = _encode_icon(config.get('metadata', 'iconfile', fallback='icon.example.png')),
        ),
        caName = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, config.get('ca', 'C', fallback='US')),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, config.get('ca', 'O', fallback='Generic')),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'Authenticator Attestation'),
            x509.NameAttribute(NameOID.COMMON_NAME, config.get('ca', 'CN', fallback='Attestation Root CA'))
        ]),
        certName = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, config.get('cert', 'C', fallback='US')),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, config.get('cert', 'O', fallback='Generic')),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'Authenticator Attestation'),
            x509.NameAttribute(NameOID.COMMON_NAME, config.get('cert', 'CN', fallback='Token Attestation'))
        ]),
        fido2 = FIDO2Config(
            aaguid = aaguid,
            aaguidExt = x509.UnrecognizedExtension(fidoAAGUIDExtensionOID, aaguid_bin),
            oidExt = x509.UnrecognizedExtension(x509.ObjectIdentifier(config.get('fido2', 'devns', fallback='1.3.6.1.4.1.0.2')), 
                config.get('fido2', 'devid', fallback='1.3.6.1.4.1.0.1.1').encode('ASCII'))
        ),
        fidesmo = FidesmoConfig(
            title = config.get('fidesmo', 'title', fallback='Generic FIDO'),
            description = config.get('fidesmo', 'description', fallback='Generic FIDO description.'),
            issuerAccountId = int(config.get('fidesmo', 'issuerAccountId', fallback=0)),
            executableLoadFile = config.get('fidesmo', 'executableLoadFile', fallback='A0000006472F00'),
            executableModule = config.get('fidesmo', 'executableModule', fallback='A0000006472F0001'),
            application = config.get('fidesmo', 'application', fallback='A0000006472F0001'),
            waitingMessage = config.get('fidesmo', 'waitingMessage', fallback='Please wait while the attestation certificate is loaded.'),
            successMessage = config.get('fidesmo', 'successMessage', fallback='Installation successful.'),
            failureMessage = config.get('fidesmo', 'failureMessage', fallback='Installation failure.')
        )
    )
