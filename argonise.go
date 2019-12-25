package main

import (
	"flag"
	"fmt"
	"os"
)

//Argon has two purposes. One as a library to allow the programmatic encryption and decryption of data; the
//other as a program which performs the encryption and decryption of files from the command line. (The
//idea being that a file would normally be kept in encrypted form, but might occasionally be decrypted
//if it had to be edited and then re-encrypted). This mimics the behaviour of ansible-vault.

func main() {
	var keyfile string
	var passphrase string
	var showversion bool
	flag.StringVar(&keyfile, "keyfile", "", "Path to file containing decryption password")
	flag.StringVar(&passphrase, "password", "", "Decryption password")
	flag.BoolVar(&showversion, "v", false, "Show version and exit")
	flag.Parse()
	if showversion {
		fmt.Println("argonise ver 1.0")
	} else if keyfile != "" && passphrase != "" {
		fmt.Println("keyfile and password options are mutually exclusive")
		os.Exit(1)
	} else {

	}
}
