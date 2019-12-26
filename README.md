# argon
Simple symmetric encryption and on the fly decryption in Go

Argon implements AES 256 encryption on files. The idea is that 
files containing sensitive information (e.g. API credentials or
the like) can normally be stored in encrypted form and then 
decrypted on the fly by applications which need to use the 
sensitive information.

It is (deliberately) similar to the facilities offered by
Ansible Vault, and has been developed because Ansible Vault
may only be used programmatically by Python on Linux platforms.

(Come the revolution, when the entire world uses Python/Linux)
this won't be a problem. But for the time being this is a workaround.

Argon consists of two components. 

1. The Argon package which contains the routines which perform 
the actual key setup, encryption and decryption.
1. The `argonise` application which allows the encryption 
and decryption of files from the command line.

# The Argon package

To use Argon, you must first create an Argon object by calling
`argon.New` with a suitable passphrase

```go
	// Setup the Argon object with the passphrase
	if a, err = argon.New(passphrase); err != nil {
		fmt.Println(err.Error())
		os.Exit(ErrEncryption)
	}
```
Once setup to encrypt a piece of plaintext or decrypt a piece
of ciphertext, use the `argon.EncryptText` and `argon.DecryptText`
methond respectively e.g. 

```go
	if encrypt {
		if dst, err = a.EncryptText(src); err != nil {
			fmt.Println(err.Error())
			os.Exit(ErrEncryption)
		}
	} else {
		if dst, err = a.DecryptText(src); err != nil {
			fmt.Println(err.Error())
			os.Exit(ErrEncryption)
		}
	}
```

# The `argonise` utility

We need a way to encrypt the sensitive information from the 
command line in the first place and also to decrpyt it if we 
want to edit it. This is where `argonise` comes in.

## Flags

The following options are available

| Flag                    | Effect                                   |
| ----------------------- | ---------------------------------------- |
| `--v`                   | Print the version number and quit        |
| `--keyfile <path>`      | Path to a file containing the passphrase |
| `--passphrase <phrase>` | Passphrase to use                        |   

* If the `--passphrase` option is specified then the keyfile will be 
ignored. 
* If neither `--passphrase` nor `--keyfile` is specified, by 
default `argonise` will look for a passphrase in the `.secret` file in 
the local directory.
* For version information to work it is necessary to build the software
using the Makefile as this performs the necessary interpolation of 
symbols at link-time.

## Syntax
```shell script
$ argonise {help|encrypt filename|decrypt filename}
```

## Example
