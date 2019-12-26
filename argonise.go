package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

//Argon has two purposes. One as a library to allow the programmatic encryption and decryption of data; the
//other as a program which performs the encryption and decryption of files from the command line. (The
//idea being that a file would normally be kept in encrypted form, but might occasionally be decrypted
//if it had to be edited and then re-encrypted). This mimics the behaviour of ansible-vault.

func GetPassphrase(keyfile string) (string, error) {
	// Gets the passphrase stored in the named file
	var err error
	var buffer []byte
	var phrase string

	if buffer, err = ioutil.ReadFile(keyfile); err != nil {
		return phrase, fmt.Errorf("GetPassphrase: Error opening keyfile: %s", err.Error())
	}
	phrase = strings.TrimSpace(string(buffer))

	if len(phrase) == 0 {
		return phrase, fmt.Errorf("GetPassphrase: no passphrase in file %s", keyfile)
	}

	return phrase, nil
}

const (
	ErrBadArgs int = 1 << iota
	ErrBadKeyFile
	ErrEncryptionFailed
)

func EncryptInSitu(filename string) error {
	return nil
}

func DecryptInSitu(filename string) error {
	return nil
}

func ShowHelp() {
	const text = `
Argonise is a tool which symmetrically encrypts and decrypts
files in-situ using a passphrase. A file can only be decrypted
using the same passphrase used in encrypting it.

Usage is

  argonise [--keyfile filename|--passprhase phrase] {help|encrypt|decrypt} filename

The passphrase can be secified on the command line using the --passphrase option 
(note that passphrases containing spaces or other special characters will have to
be enclosed in quotes to prevent the shell from interpreting them). 

If the --passphrase option is not specified, then argonise will look for a passphrase
in a keyfile specified by the --keyfile option. If the keyfile location isn't specified, 
then argonise will attempt to use the file .secret 
`
	fmt.Println(text)
	os.Exit(0)
}

func GetArguments() (passphrase string, filename string, encrypt bool) {
	var keyfile string
	var showversion bool
	var err error
	var args []string

	flag.StringVar(&keyfile, "keyfile", ".secret", "Path to file containing decryption password")
	flag.StringVar(&passphrase, "passphrase", "", "Decryption passphrase")
	flag.BoolVar(&showversion, "v", false, "Show version and exit")
	flag.Parse()
	args = flag.Args()

	if showversion {
		fmt.Println("argonise ver 1.0")
		os.Exit(0)
	}

	if len(args) > 0 && strings.ToLower(args[0]) == "help" {
		ShowHelp()
		os.Exit(0)
	}

	if len(args) != 2 {
		fmt.Println("Syntax: argonise {--keyfile filename|--passphrase phrase} {help|encrypt filename|decrypt filename")
		os.Exit(ErrBadArgs)
	}

	filename = args[1]

	switch strings.ToLower(args[0]) {
	case "encrypt":
		encrypt = true
	case "decrypt":
		encrypt = false
	default:
		fmt.Printf("Unrecognised command %s. Options are help, encrypt or decrypt\n", args[0])
		os.Exit(ErrBadArgs)
	}

	if keyfile != "" {
		if passphrase, err = GetPassphrase(keyfile); err != nil {
			fmt.Println(err.Error())
			os.Exit(ErrBadKeyFile)
		}
	}

	return
}
func main() {
	passphrase, filename, encrypt := GetArguments()
	fmt.Printf("Passphrase is '%s' Filename is '%s' Encrypt is %t\n", passphrase, filename, encrypt)
}
