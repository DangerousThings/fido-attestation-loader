import os, argparse, getpass


def parse():
    parser = argparse.ArgumentParser(description = 'Manage attestation certificates and certificate authorities')

    parser.add_argument('-l', '--list-readers', action='store_true', dest='listreaders', 
        help='list available PC/SC readers')
        
    actions = parser.add_subparsers(help='desired action to perform', dest='action') 

    # Attestation certificate
    parser_handle_cert = argparse.ArgumentParser(add_help=False)
    parser_handle_cert.add_argument('-c', '--certificate', nargs='?', dest='certfile', type=str, 
        const='attestation.der', default='attestation.der', 
        help='filename of the public attestation certificate (default: attestation.der)')

    parser_handle_cert_pkey = argparse.ArgumentParser(add_help=False)
    parser_handle_cert_pkey.add_argument('-k', '--private-key', nargs='?', 
        dest='privkeyfile', type=str, const='attestation_key.p8', default='attestation_key.p8', 
        help='filename of the private attestation key (default: attestation_key.p8)')
    parser_handle_cert_pkey.add_argument('-p', '--private-key-passphrase', nargs='?', 
        dest='privkeypassphrase', type=str,
        help='passphrase to de/encrypt the private attestation key')

    # CA certificate
    parser_handle_ca = argparse.ArgumentParser(add_help=False)
    parser_handle_ca.add_argument('-cac', '--certificate-authority', nargs='?', 
        dest='cacertfile', type=str, const='ca.der', default='ca.der', 
        help='filename of the public certificate authority certificate (default: ca.der)')

    parser_handle_ca_pkey = argparse.ArgumentParser(add_help=False)
    parser_handle_ca_pkey.add_argument('-cak', '--certificate-authority-key', 
        nargs='?', dest='caprivkeyfile', type=str, const='ca_key.p8', default='ca_key.p8', 
        help='filename of the private certificate authority key (default: ca_key.p8)')
    parser_handle_ca_pkey.add_argument('-cap', '--certificate-authority-key-passphrase', 
        nargs='?', dest='caprivkeypassphrase', type=str,
        help='passphrase to de/encrypt the private certificate authority key')

    # Generation options
    parser_handle_create = argparse.ArgumentParser(add_help=False)
    parser_handle_create.add_argument('-d', '--days', nargs='?', dest='days', type=int, 
        const=3652, default=3652, 
        help='certificate authority validity duration in days (default: 3652 = 10 years)')
    parser_handle_create.add_argument('-o', '--overwrite', dest='overwrite', type=bool, 
        default=False, action = argparse.BooleanOptionalAction,
        help='allow overwriting existing files')

    # Interfacing options
    parser_handle_load = argparse.ArgumentParser(add_help=False)
    parser_handle_load.add_argument('-r', '--reader', nargs='?', dest='reader', type=int, 
        const=0, default=0, 
        required=False, help='index of the PC/SC reader to use (default: 0)')

    # CA action
    parser_ca = actions.add_parser('ca', help='manage certificate authorities')
    subparsers_ca = parser_ca.add_subparsers(
        help='desired action to perform on a certificate authority', 
        dest='verb', required=True) 
    
    # CA CREATE action
    parser_ca_create = subparsers_ca.add_parser('create', 
        parents=[parser_handle_ca, parser_handle_ca_pkey, parser_handle_create], 
        help='create a new certificate authority')

    # CERT action
    parser_cert = actions.add_parser('cert', help='manage attestation certificates')
    subparsers_cert = parser_cert.add_subparsers(
        help='desired action to perform on an attestation certificate', 
        dest='verb', required=True) 

    # CERT CREATE action
    parser_cert_create = subparsers_cert.add_parser('create', 
        parents=[parser_handle_cert, parser_handle_cert_pkey, 
            parser_handle_ca, parser_handle_ca_pkey, parser_handle_create], 
        help='create a new attestation certificate')
    
    # CERT SHOW action
    parser_cert_show = subparsers_cert.add_parser('show', 
        parents=[parser_handle_cert, parser_handle_cert_pkey], 
        help='show details of an existing attestation certificate')

    # CERT VAL action
    parser_cert_validate = subparsers_cert.add_parser('validate', 
        parents=[parser_handle_cert, parser_handle_ca], 
        help='validate an existing attestation certificate against a certificate authority')

    # CERT UPLOAD action
    parser_cert_validate = subparsers_cert.add_parser('upload', 
        parents=[parser_handle_cert, parser_handle_load], 
        help='upload an existing public attestation certificate to a hardware token')

    args = parser.parse_args()
    return (parser, args)


def validate(parser, args):
    if(args.listreaders):
        return

    if(args.action is None):
        parser.print_help()
        exit(1)

    if(args.action == 'ca'):
        if(args.verb == 'create'):
            print('info: Creating a new certificate authority')
    elif(args.action == 'cert'):
        if(args.verb == 'create'):
            print('info: Creating a new attestation certificate')
        elif(args.verb == 'show'):
            print('info: Showing an existing attestation certificate')
        elif(args.verb == 'validate'):
            print('info: Validating an existing attestation certificate against a certificate authority')
        elif(args.verb == 'upload'):
            print('info: Uploading a public attestation certificate to a hardware token')

    if(args.action == 'cert'):
        if(args.verb == 'create'):
            if(os.path.isfile(args.certfile) and (not args.overwrite)):
                print('error: Public attestation certificate file \'' + args.certfile + 
                    '\' already exists. Run with \'-o\' to enable overwriting files.')
                exit(1)
            if(os.path.isfile(args.privkeyfile) and (not args.overwrite)):
                print('error: Private attestation key file \'' + args.privkeyfile + 
                    '\' already exists. Run with \'-o\' to enable overwriting files.')
                exit(1)
        if(args.verb == 'create' or args.verb == 'show'):
            if(args.privkeypassphrase is None):
                if(args.verb == 'create'):
                    pw1 = getpass.getpass('prompt: No passphrase to encrypt the private attestation key specified, ' + 
                        'please create passphrase: ')
                    pw2 = getpass.getpass('prompt: Re-type passphrase for confirmation: ')
                    if(pw1 == pw2):
                        args.privkeypassphrase = pw1
                    else:
                        print('error: Passphrases do not match.')
                        exit(1)
                else:
                    args.privkeypassphrase = getpass.getpass('prompt: No passphrase to decrypt the private attestation ' + 
                        'key specified, please enter passphrase: ')

    if(args.action == 'ca'):
        if(os.path.isfile(args.cacertfile) and (not args.overwrite)):
            print('error: Public certificate authority file \'' + args.cacertfile + 
                '\' already exists. Run with \'-o\' to enable overwriting files.')
            exit(1)
        if(os.path.isfile(args.caprivkeyfile) and (not args.overwrite)):
            print('error: Private certificate authority key file \'' + args.caprivkeyfile + 
                '\' already exists. Run with \'-o\' to enable overwriting files.')
            exit(1)

    if((args.action == 'cert' and args.verb == 'create') or args.action == 'ca'):
        if(args.caprivkeypassphrase is None):
            if(args.action == 'ca'):
                pw1 = getpass.getpass('prompt: No passphrase to encrypt the certificate authority private key specified, ' + 
                    'please create passphrase: ')
                pw2 = getpass.getpass('prompt: Re-type passphrase for confirmation: ')
                if(pw1 == pw2):
                    args.caprivkeypassphrase = pw1
                else:
                    print('error: Passphrases do not match.')
                    exit(1)
            else:
                args.caprivkeypassphrase = pw1 = getpass.getpass('prompt: No passphrase to decrypt the certificate authority ' + 
                    'private key specified, please enter passphrase: ')

        if(args.days < 1):
            print('error: Certificate validity duration must be at least 1 day.')
            exit(1)
