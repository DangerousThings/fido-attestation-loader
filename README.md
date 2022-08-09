# FIDO Attestation Certificate Loader

Tool to generate certificate authorities and attestation certificates, and deploy them to [vk-u2f](https://github.com/VivoKey/vk-u2f), [u2f-javacard](https://github.com/darconeous/u2f-javacard), or [Fidesmo](https://fidesmo.com/).

This tool assumes NFC transport, and sets the FIDO U2F certificate transports extension accordingly.

The generated certificate authorities use the `SECP384R1` elliptic curve, and the generated attestation certificates use the `SECP256R1` elliptic curve.

## Setup

Install [Python 3](https://www.python.org/downloads/) and Pip (usually packaged with Python), both are probably available via your package manager. Use Pip in the terminal to install the requirements: 

```
pip install -r requirements.txt
``` 

Required modules are `cryptography`, `asn1`, and `pyscard`. The executable might also be called `pip3`. If you use NixOS, Flake and EnvRC files are provided.

### Settings File

Before you start, copy the provided `settings.ini.example` file to `settings.ini`, and adjust the parameters. Enter the metadata of your token and company, and specify your AAGUID and assigned OIDs.

If you want to deploy to Fidesmo, fill out that section with your data as well.

### Private Key Encryption

The certificate authority private key, as well as the attestation private key are encrypted using a user-specified passphrase. To interact with the keys, the passphrase has to be specified in one on three ways for various commands:

1. Interactively during script runtime, by entering it when the script asks for input.
2. As a commandline parameter, by using the `-p` and `-cap` parameters.
3. Inside a text file, by optionally specifying the file path using the `-pf` and `-capf` parameters. The default file names are `attestation_key.pass` and `ca_key.pass`.

Option one requires an interactive terminal, which might be a problem if you want to pipe the script output to another program. When using option two, the passphrase might be logged into your terminal history file in clear text. Option three requires you to protect the passphrase file yourself however you see fit, e.g. by bind-mounting it and restricting access.


## Creating a New Certificate Chain

Create a new certificate authority:

```
./attestation.py ca create
```

Create a new attestation certificate, and sign it using the existing certificate authority:

```
./attestation.py cert create
```

You can use the `-o` flag to overwrite existing files, but be careful. These scripts also require passphrases, see above for details.

To verify the signature of an attestation certificate against a certificate authority:

```
./attestation.py cert validate
```

All these commands accept optional parameters to specify the file names of all certificate and key files, use the `-h` help parameter to get detailed information.

## Deploying an Attestation Certificate

### Directly Uploading to a Physical Card

To push an attestation certificate to a card, you first have to generate the installation parameter, which contains the private key:

```
./attestation.py cert show
```

You can use the format flag to only print the installation parameter by itself by specifying `-f parameter`. The `cert show` command also requires a passphrase, see above.

Next, install the applet using e.g. Global Platform, and specify the installation parameter.

After the installation, upload the public attestation certificate:

```
./attestation.py cert upload
```

You might have to specify the index of your PC/SC reader using the `-r` flag (use `./attestation.py -l` to list connected readers).

Both the `cert show` as well as the `cert upload` command accept the mode parameter `-m`, which specifies the format to use. Use `-m fido2` (the default) for FIDO2 (vk-u2f), and `-m u2f` for FIDO1 U2F (u2f-javacard).

### Updating a Fidesmo Service Recipe

To generate a Fidesmo service JSON, run `./attestation.py cert show -f fidesmo` . Once you are happy with the output, you can pipe it into `curl` in order to upload it to Fidesmo:

```
./attestation.py cert show -f fidesmo | curl -H "Content-Type: application/json" -X PUT "https://api.fidesmo.com/apps/APPID/services/SERVICEID/recipe" -d @- -u "USERNAME"
```

Note that this requires you to either specify the attestation private key passphrase on the commandline (`-p`, not recommended), or provide a passphrase file. This is because the interactive input causes problems with the pipe. You can also perform this operation in two commands, and write the Fidesmo config to a text file in between. This however exposes the private key to your storage, which is encoded in the Fidesmo configuration.

Replace `APPID` with the application ID of your Fidesmo app, `SERVICEID` with the ID of the service you want to update (e.g. `install`), and `USERNAME` with your API username. `curl` will then ask you for your API password interactively, again to prevent your password landing in the terminal history file.


## Complete Commandline Reference

Use `./attestation.py -hd` to print this information.

```
usage: attestation.py [-h] [-hd] [-l] [-s [SETTINGS]] {ca,cert} ...

Manage attestation certificates and certificate authorities

positional arguments:
  {ca,cert}             desired action to perform
    ca                  manage certificate authorities
    cert                manage attestation certificates

options:
  -h, --help            show this help message and exit
  -hd, --help-documentation
                        Print the complete help documentation
  -l, --list-readers    list available PC/SC readers
  -s [SETTINGS], --settings [SETTINGS]
                        settings file for metadata (default: settings.ini)

usage: attestation.py ca create [-h] [-cac [CACERTFILE]] [-cak [CAPRIVKEYFILE]] [-cap [CAPRIVKEYPASSPHRASE]] [-capf [CAPRIVKEYPASSPHRASEFILE]] [-d [DAYS]]
                                [-o | --overwrite | --no-overwrite]

options:
  -h, --help            show this help message and exit
  -cac [CACERTFILE], --certificate-authority [CACERTFILE]
                        filename of the public certificate authority certificate (default: ca.der)
  -cak [CAPRIVKEYFILE], --certificate-authority-key [CAPRIVKEYFILE]
                        filename of the private certificate authority key (default: ca_key.p8)
  -cap [CAPRIVKEYPASSPHRASE], --certificate-authority-key-passphrase [CAPRIVKEYPASSPHRASE]
                        passphrase to de/encrypt the private certificate authority key
  -capf [CAPRIVKEYPASSPHRASEFILE], --certificate-authority-key-passphrase-file [CAPRIVKEYPASSPHRASEFILE]
                        file that contains the passphrase to de/encrypt the private certificate authority key (default: ca_key.pass)
  -d [DAYS], --days [DAYS]
                        certificate authority validity duration in days (default: 3652 = 10 years)
  -o, --overwrite, --no-overwrite
                        allow overwriting existing files (default: False)

usage: attestation.py cert create [-h] [-c [CERTFILE]] [-k [PRIVKEYFILE]] [-p [PRIVKEYPASSPHRASE]] [-pf [PRIVKEYPASSPHRASEFILE]] [-cac [CACERTFILE]] [-cak [CAPRIVKEYFILE]]
                                  [-cap [CAPRIVKEYPASSPHRASE]] [-capf [CAPRIVKEYPASSPHRASEFILE]] [-d [DAYS]] [-o | --overwrite | --no-overwrite]

options:
  -h, --help            show this help message and exit
  -c [CERTFILE], --certificate [CERTFILE]
                        filename of the public attestation certificate (default: attestation.der)
  -k [PRIVKEYFILE], --private-key [PRIVKEYFILE]
                        filename of the private attestation key (default: attestation_key.p8)
  -p [PRIVKEYPASSPHRASE], --private-key-passphrase [PRIVKEYPASSPHRASE]
                        passphrase to de/encrypt the private attestation key
  -pf [PRIVKEYPASSPHRASEFILE], --private-key-passphrase-file [PRIVKEYPASSPHRASEFILE]
                        file that contains the passphrase to de/encrypt the private attestation key
  -cac [CACERTFILE], --certificate-authority [CACERTFILE]
                        filename of the public certificate authority certificate (default: ca.der)
  -cak [CAPRIVKEYFILE], --certificate-authority-key [CAPRIVKEYFILE]
                        filename of the private certificate authority key (default: ca_key.p8)
  -cap [CAPRIVKEYPASSPHRASE], --certificate-authority-key-passphrase [CAPRIVKEYPASSPHRASE]
                        passphrase to de/encrypt the private certificate authority key
  -capf [CAPRIVKEYPASSPHRASEFILE], --certificate-authority-key-passphrase-file [CAPRIVKEYPASSPHRASEFILE]
                        file that contains the passphrase to de/encrypt the private certificate authority key (default: ca_key.pass)
  -d [DAYS], --days [DAYS]
                        certificate authority validity duration in days (default: 3652 = 10 years)
  -o, --overwrite, --no-overwrite
                        allow overwriting existing files (default: False)

usage: attestation.py cert show [-h] [-c [CERTFILE]] [-k [PRIVKEYFILE]] [-p [PRIVKEYPASSPHRASE]] [-pf [PRIVKEYPASSPHRASEFILE]] [-m [{u2f,u2fci,fido2}]]
                                [-f [{human,parameter,fidesmo}]]

options:
  -h, --help            show this help message and exit
  -c [CERTFILE], --certificate [CERTFILE]
                        filename of the public attestation certificate (default: attestation.der)
  -k [PRIVKEYFILE], --private-key [PRIVKEYFILE]
                        filename of the private attestation key (default: attestation_key.p8)
  -p [PRIVKEYPASSPHRASE], --private-key-passphrase [PRIVKEYPASSPHRASE]
                        passphrase to de/encrypt the private attestation key
  -pf [PRIVKEYPASSPHRASEFILE], --private-key-passphrase-file [PRIVKEYPASSPHRASEFILE]
                        file that contains the passphrase to de/encrypt the private attestation key
  -m [{u2f,u2fci,fido2}], --mode [{u2f,u2fci,fido2}]
                        Applet variant to handle (default: fido2)
  -f [{human,parameter,fidesmo}], --format [{human,parameter,fidesmo}]
                        Format of the certificate to display

usage: attestation.py cert validate [-h] [-c [CERTFILE]] [-cac [CACERTFILE]]

options:
  -h, --help            show this help message and exit
  -c [CERTFILE], --certificate [CERTFILE]
                        filename of the public attestation certificate (default: attestation.der)
  -cac [CACERTFILE], --certificate-authority [CACERTFILE]
                        filename of the public certificate authority certificate (default: ca.der)

usage: attestation.py cert upload [-h] [-c [CERTFILE]] [-r [READER]] [-m [{u2f,u2fci,fido2}]] [-lo | --log--apdus-only | --no-log--apdus-only]

options:
  -h, --help            show this help message and exit
  -c [CERTFILE], --certificate [CERTFILE]
                        filename of the public attestation certificate (default: attestation.der)
  -r [READER], --reader [READER]
                        index of the PC/SC reader to use (default: 0)
  -m [{u2f,u2fci,fido2}], --mode [{u2f,u2fci,fido2}]
                        Applet variant to handle (default: fido2)
  -lo, --log--apdus-only, --no-log--apdus-only
                        only display APDUs without sending (default: False)
```
