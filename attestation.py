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
        pass
    elif(args.action == 'cert'):
        if(args.verb == 'create'):
            cert.create(args)
        elif(args.verb == 'show'):
            pass
        elif(args.verb == 'validate'):
            pass
        elif(args.verb == 'upload'):
            pass
