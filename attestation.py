#!/usr/bin/env python3

import attestation.argparser as arg
import attestation.certificate as cert

if __name__ == '__main__':
    args = arg.parse()
    arg.validate(args)

    if(args.listreaders):
        print('Not implemented')
        exit(1)

    if(args.action == 'ca'):
        if(args.verb == 'create'):
            cert.create_ca(args)
        elif(args.verb == 'renew'):
            print('Not implemented')
            exit(1)
    elif(args.action == 'cert'):
        if(args.verb == 'create'):
            cert.create_cert(args)
        elif(args.verb == 'show'):
            print('Not implemented')
            exit(1)
        elif(args.verb == 'validate'):
            print('Not implemented')
            exit(1)
        elif(args.verb == 'upload'):
            print('Not implemented')
            exit(1)
