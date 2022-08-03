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


def upload_cert(args):
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
    with open(args.certfile, 'rb') as f:
        cert_der = f.read()
    cert_print_info(x509.load_der_x509_certificate(cert_der), 'attestation certificate')

    connection = red.createConnection()
    connection.connect()
    # Select the applet
    print('info: Sending applet selection') 
    data, sw1, sw2 = connection.transmit(
        [0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01])
    if(sw1 == 0x90 and sw2 == 0x00):
        print('success: Applet selected, card response is ok')
    else:
        print('error: Card response: ' + f'{sw1:02x}' + ' ' + f'{sw2:02x}, aborting upload')
        connection.disconnect()
        exit(1)
    # Send the certificate in chunks
    for offset in range(0, len(cert_der), 128):
        length = min(128, len(cert_der) - offset)
        print('info: Sending data chunk, offset = ' + str(offset) + ', length = ' + str(length))
        data, sw1, sw2 = connection.transmit([0x80, 0x01] + 
            list(offset.to_bytes(2, byteorder='big')) + list(length.to_bytes(1, byteorder='big')) + 
            list(cert_der[offset:(offset + length)]))
        if(sw1 == 0x90 and sw2 == 0x00):
            print('success: Data chunk transferred, card response is ok')
        else:
            print('error: Card response: ' + f'{sw1:02x}' + ' ' + f'{sw2:02x}, aborting upload')
            connection.disconnect()
            exit(1)
    connection.disconnect()
