package argon

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

// Simple library to support symmetric encryption and decryption of files, including on-the-fly
// decryption. The Golang equivalent of the Krypton Python libraries.
//
// The purpose of Argon is to allow sensitive information (e.g. credentials) to be stored in text files
// in which can then be encrypted and decrypted in situ from the command line or decrypted on the fly
// by a program.
//
// This technique grew out of using Ansible Vault to encrypt configuration files before
// committing them to Git. So, ordinarily, the files would be stored as plaintext locally,
// and then only encrypted using Ansible Vault prior to being committed/pushed. However,
// Python scripts have access to the Ansible Vault libraries, and so it was possible to
// have sensitive data permanently encrypted, and only decrypted when the config file needed
// to be edited, making it inherently more secure.
//
// Ansible Vault only exists under Linux, and so a Python library called Krypton was
// developed to allow on-the-fly symmetric decryption etc. under other OS. Argon is a
// sister project for the Go language.
//
// NOTE THAT ARGON AND KRYPTON FILE FORMATS ARE INCOMPATIBLE. YOU CAN'T DECRYPT AN
// ARGON FILE USING KRYPTON AND VICE VERSA.

type PassPhrase string

func (p PassPhrase) String() string {
	var r = []rune(p)
	for c := 1; c < len(r)-1; c++ {
		r[c] = '*'
	}
	return string(r)
}

var nonce = []byte{0x26, 0x7e, 0x67, 0x04, 0xee, 0x7f, 0x13, 0x29, 0x9e, 0x6e, 0x50, 0x85}

type Argon struct {
	phrase PassPhrase   // Passphrase used for encryption
	key    []byte       // Checksum, in slice format (used as encryption key)
	cipher cipher.Block // AES block cipher
	gcm    cipher.AEAD  // Galois counter
}

func (a Argon) String() string {
	// Return an obscured version of the passphrase so sausages -> s******s
	return fmt.Sprintf("%s -> %s", a.phrase, hex.EncodeToString(a.key))
}

func New(phrase string) (*Argon, error) {
	// Generate an Argon object. Take the passphrase (which may be of arbitrary length) and convert it to
	// a 256-bit hash using SHA-256. Then use this as the basis of an AES256 cipher. Then produce a Galois
	// counter for that cipher (essentially making the AES block-cipher into a stream-cipher
	var a = new(Argon)
	var err error
	a.phrase = PassPhrase(phrase)
	sum := sha256.Sum256([]byte(a.phrase))
	a.key = sum[:]
	if a.cipher, err = aes.NewCipher(a.key); err != nil {
		return a, fmt.Errorf("NewArgon: Error creating key: %s", err.Error())
	}
	if a.gcm, err = cipher.NewGCM(a.cipher); err != nil {
		return a, fmt.Errorf("NewArgon: Error creating Galois counter: %s", err.Error())
	}
	return a, nil
}

func (a *Argon) Encrypt(src []byte) []byte {
	// Simple wrapper function to encrypt a bunch of bytes
	return a.gcm.Seal(nil, nonce, src, nil)
}

func (a *Argon) Decrypt(enc []byte) ([]byte, error) {
	// Simple wrapper to decrypt a bunch of bytes
	return a.gcm.Open(nil, nonce, enc, nil)
}

func (a *Argon) EncryptText(src string) (string, error) {
	// Encrypts a text string and formats it as a series of constant
	// width base64 encoded lines with a header and footer.

	var bob = new(strings.Builder)
	var enc = a.Encrypt([]byte(src))
	var b64 = base64.StdEncoding.EncodeToString(enc)
	var header string
	const width = 80
	header = fmt.Sprintf("--| argon |")
	header = Pad(header, width, '-')
	if strings.HasPrefix(src, header) {
		return "", fmt.Errorf("EncryptText: Text is already Argon encrypted")
	}
	var footer = Pad("--| end |", width, '-')
	bob.WriteString(fmt.Sprintf("%s\n", header))
	for _, line := range Split(b64, width) {
		bob.WriteString(fmt.Sprintf("%s\n", line))
	}
	bob.WriteString(fmt.Sprintf("%s\n", footer))
	return bob.String(), nil
}

func (a *Argon) DecryptText(src string) (string, error) {
	// Takes an Argon encrypted piece of text (as returned by
	// Argon.EncryptText and converts it back to plaintext.

	const header = "--| argon "
	var raw []byte
	var err error
	var decrypted []byte
	var lines = strings.Split(src, "\n")
	if !strings.HasPrefix(lines[0], header) {
		return "", fmt.Errorf("DecryptText: Text does not appear to be Argon encrypted")
	}
	var b64 = strings.Join(lines[1:len(lines)-2], "")
	if raw, err = base64.StdEncoding.DecodeString(b64); err != nil {
		return "", fmt.Errorf("DecryptText: Can't decode base64: %s", err.Error())
	}
	if decrypted, err = a.Decrypt(raw); err != nil {
		return "", fmt.Errorf("DecryptText: Can't decrpyt: %s", err.Error())
	}
	return string(decrypted), nil
}

func Pad(src string, width int, padding rune) string {
	// Pads src to a particular with by adding padding
	if len(src) >= width {
		return src
	}
	var r = []rune(src)
	for i := len(src); i < width; i++ {
		r = append(r, padding)
	}
	var dst = string(r)
	return dst
}

func Split(src string, width int) []string {
	// Splits a string into chunks of a fixed size
	if width <= 0 {
		panic(fmt.Errorf("Split: string width must be greater than zero"))
	}
	var dst []string
	var r = []rune(src)
	var chunk int
	var chunks = len(src) / width
	for chunk = 0; chunk < chunks; chunk++ {
		dst = append(dst, string(r[chunk*width:(chunk+1)*width]))
	}
	if len(src)%width != 0 { // Are there any leftovers?
		dst = append(dst, string(r[chunk*width:]))
	}
	return dst
}
