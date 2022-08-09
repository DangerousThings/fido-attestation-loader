#!/usr/bin/env python3

import attestation.argparser as arg
import attestation.certificate as cert
import attestation.show as show
import attestation.loader as load
import attestation.config as config


if __name__ == '__main__':
    parser, args = arg.parse()
    arg.validate(parser, args)

    if(args.listreaders):
        load.list_readers()
        exit(1)

    conf = config.parse(args)
    
    if(args.action == 'ca'):
        if(args.verb == 'create'):
            cert.create_ca(args, conf)
    elif(args.action == 'cert'):
        if(args.verb == 'create'):
            cert.create_cert(args, conf)
        elif(args.verb == 'show'):
            show.show_cert(args, conf)
        elif(args.verb == 'validate'):
            cert.validate_cert(args)
        elif(args.verb == 'upload'):
            load.upload_cert(args)
