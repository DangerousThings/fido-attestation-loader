from smartcard.System import readers
from cryptography import x509
from .certificate import cert_print_info


def list_readers():
    redlist = readers()
    if(len(redlist) == 0):
        print('warning: No PC/SC readers found')
        return
    redlist.sort(key=str)
    print('info: Available PC/SC readers (' + str(len(redlist)) + '):')
    for i, reader in enumerate(redlist):
        print(str(i) + ': ' + str(reader))


def generate_apdus(cert_der, args):
    apdus = []
    # Select the applet
    apdus.append([0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01])
    if(args.mode == 'u2f' or args.mode == 'u2fci'):
        # Send the certificate in distinct chunks
        for offset in range(0, len(cert_der), 128):
            length = min(128, len(cert_der) - offset)
            apdus.append([0x80, 0x01] + list(offset.to_bytes(2, byteorder='big')) + 
                list(length.to_bytes(1, byteorder='big')) + list(cert_der[offset:(offset + length)]))
    elif(args.mode == 'fido2'):
        # Send the certificate as a chained APDU
        cert_der = [0x42] + list(cert_der)
        for offset in range(0, len(cert_der), 255):
            length = min(255, len(cert_der) - offset)
            cla = 0x80
            if(len(cert_der) - offset > 255): cla |= 0x10
            apdus.append([cla, 0x10, 0x00, 0x00, length] + cert_der[offset:(offset + length)])
    return apdus


def upload_cert(args):
    with open(args.certfile, 'rb') as f:
        cert_der = f.read()
        cert_print_info(x509.load_der_x509_certificate(cert_der), 'attestation certificate')

    apdus = generate_apdus(cert_der, args)
    if(args.apduonly):
        print('info: Generated ' + str(len(apdus)) + ' APDUs:')
        for i, apdu in enumerate(apdus):
            print('info: Index: ' + str(i) + ', Length: ' + str(len(apdu)) + ', Data: ' + bytes(apdu).hex())
        exit(0)

    redlist = readers()
    if(len(redlist) == 0):
        print('error: No PC/SC readers found')
        exit(1)
    if(args.reader < 0 or args.reader >= len(redlist)):
        print('error: Specified reader index is out of range')
        exit(1)
    redlist.sort(key=str)
    red = redlist[args.reader]
    print('info: Using reader ' + str(args.reader) + ': ' + str(red))

    connection = red.createConnection()
    connection.connect()
    for i, apdu in enumerate(apdus):
        data, sw1, sw2 = connection.transmit(apdu)
        if(sw1 == 0x90 and sw2 == 0x00):
            print('success: APDU ' + str(i + 1) + '/' + str(len(apdus)) +
                ' (' + str(len(apdu)) + ' bytes) transferred, card response is ok')
        else:
            print('error: Card response: ' + f'{sw1:02x}' + ' ' + f'{sw2:02x}, aborting upload')
            connection.disconnect()
            exit(1)
    connection.disconnect()
