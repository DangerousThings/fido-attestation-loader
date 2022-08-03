#!/usr/bin/env python3

import attestation.argparser as arg
import attestation.certificate as cert
import attestation.loader as load


if __name__ == '__main__':
    parser, args = arg.parse()
    arg.validate(parser, args)

    if(args.listreaders):
        load.list_readers()
    if(args.action == 'ca'):
        if(args.verb == 'create'):
            cert.create_ca(args)
    elif(args.action == 'cert'):
        if(args.verb == 'create'):
            cert.create_cert(args)
        elif(args.verb == 'show'):
            cert.show_cert(args)
        elif(args.verb == 'validate'):
            cert.validate_cert(args)
        elif(args.verb == 'upload'):
            load.upload_cert(args)
