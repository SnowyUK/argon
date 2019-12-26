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

## Example session

```text
snowy@merlin:~/argon$ make
go build -mod=vendor -o bin/argonise -ldflags "-s -X main.BuildDate=$(date +'%Y-%m-%dT%H:%M:%S') -X main.GitHash=$(git rev-parse HEAD) -X main.Version=$(git describe --tags 2> /dev/null || echo dev-version)"
snowy@merlin:~/argon$ bin/argonise -v
argonise 1.1 (7d12ca4c) Built 2019-12-26T18:20:12
snowy@merlin:~/argon$ cat Jabberwocky.txt 
’Twas brillig, and the slithy toves
      Did gyre and gimble in the wabe:
All mimsy were the borogoves,
      And the mome raths outgrabe.

“Beware the Jabberwock, my son!
      The jaws that bite, the claws that catch!
Beware the Jubjub bird, and shun
      The frumious Bandersnatch!”

He took his vorpal sword in hand;
      Long time the manxome foe he sought—
So rested he by the Tumtum tree
      And stood awhile in thought.

And, as in uffish thought he stood,
      The Jabberwock, with eyes of flame,
Came whiffling through the tulgey wood,
      And burbled as it came!

One, two! One, two! And through and through
      The vorpal blade went snicker-snack!
He left it dead, and with its head
      He went galumphing back.

“And hast thou slain the Jabberwock?
      Come to my arms, my beamish boy!
O frabjous day! Callooh! Callay!”
      He chortled in his joy.

’Twas brillig, and the slithy toves
      Did gyre and gimble in the wabe:
All mimsy were the borogoves,
      And the mome raths outgrabe.
snowy@merlin:~/argon$ cat .secret 
sausages
snowy@merlin:~/argon$ 
snowy@merlin:~/argon$ bin/argonise encrypt Jabberwocky.txt 
snowy@merlin:~/argon$ cat Jabberwocky.txt 
--| argon |---------------------------------------------------------------------
EG3D32nmMRRJWaJ8Ij8kPktTaoh1Z7aYpRvvOhlNHTtiHjCdz9zSmthdw8PjvahYS3NGiMD51V50gkpw
g1X9AVKGi9aCawsySnejFjJ4V4uyy+NGLhBMAwFqcQYMqyfuE2oih7CPFiDI7lGKaAbp/KNxH398Yr1P
QQ47RMsgvk++blF0mQyDc+AGr8UDJclOxlCSF3tQiLVgHOJrbSliZFXwxVTsu2mMZMWPnlC/luUdr5Ha
NXZiEJXqRF/G6ty8k/VtQpCxHYhWWIvAWqFrJAMfPvYcv64IJZ5rBVebmER5KrPEFgmd88nyMLlRUK6y
qR7EVPTwzMKSeDGZIJhaTSs0Aeu0DtG6rRlzqVPjWBZzSb8c9AhZv3wOFfxRMH94DgfI7QLuiOS2sBub
/BO9xQrfCDR+ZPwiU8AXMM69CbdJJPTjHHSVPRD71FnaZ4VnevM6POsCNbsGVzhss92XDE+LEqTeipRb
t3gurSNZ61mcIyWqOkLMcP/ae0+DsS6Kj/9Sqrj2i9RKbahYbBDmGi7H6n6P6Y7hH/3ZxlcbZ57KgLm8
y8fKACmXMuJDsDfWtKhuSu1/DMlNdYa6vsfYVijqX7OKPsnOVjS0gVgngZ8iaqSaJmu5/Uxj5SiL0FYQ
mHK2Idk6UQOLYHPCPsAUvtf4srv6XwFuZ3Pf+AHFY0x1N46JpxW7f4gsBkeB0QHVBTIbbNKd5WKRI1qh
Z+HmuSeguPbla7i2ST25/jx0DFrtMYkcz5EPX5uPIxFTDraQaYElmOsZ31ptiKHSenvATX91nxGXEY9k
EJv6hijngEcuBeesE/H06nSWyD3uaifVZcaFNmJ5FZzNc81dJ5OJJUYE7WarMw0Jl4Ah4lei8jk7o8Pm
hs0qpPZNMApEnHcdkmyM06+9d0JrB3TVOVyExzYoS0twTY1BmpWlxD+by2xrUWRg7dT0AdhVwvgdiTVo
SSvd+zCjajOqW7W+aUDYeX2rlFNBOQRx/lHV60KrxH9n+bPoLdipZxSZIHu/DPjynMLwzmG7AgbMHpSC
39RaLYn2XJ4pUYp1mv97nNEfDiSuUwqo5wF8xMsx9CB1vOa0IzP88LW6mXy3qxFwwPrBP/WpoalTB1jn
JPMvk8HyuN1idJiq7AioxU/9ldfehO5BXplziCZcXNtPAA3rUsauMFPUyafHGA6OWu9q+hNmKGXKnx6O
oWvBkMI/9ED22gLZ891Sm4N5f6T3rh6lj3UOXV6rec4ciYuu9BFvkofl7Z2aKd/4YaejoU3nJC2YuMP0
PWhfVQ8SweaOU5/mzAJRCPfRqw7a7A/7zhbu+ixoQSKKIkVoXBx7WQ2Tj4GGlo7g8AilaJi/Kmk/zzFb
UwDGTqcpuvBhM31Os3YO1IXj/yj2LgizMQnXxw==
--| end |-----------------------------------------------------------------------
snowy@merlin:~/argon$ bin/argonise --passphrase marmalade decrypt Jabberwocky.txt  
DecryptText: Can't decrpyt: cipher: message authentication failed
snowy@merlin:~/argon$ bin/argonise decrypt Jabberwocky.txt 
snowy@merlin:~/argon$ cat Jabberwocky.txt 
’Twas brillig, and the slithy toves
      Did gyre and gimble in the wabe:
All mimsy were the borogoves,
      And the mome raths outgrabe.

“Beware the Jabberwock, my son!
      The jaws that bite, the claws that catch!
Beware the Jubjub bird, and shun
      The frumious Bandersnatch!”

He took his vorpal sword in hand;
      Long time the manxome foe he sought—
So rested he by the Tumtum tree
      And stood awhile in thought.

And, as in uffish thought he stood,
      The Jabberwock, with eyes of flame,
Came whiffling through the tulgey wood,
      And burbled as it came!

One, two! One, two! And through and through
      The vorpal blade went snicker-snack!
He left it dead, and with its head
      He went galumphing back.

“And hast thou slain the Jabberwock?
      Come to my arms, my beamish boy!
O frabjous day! Callooh! Callay!”
      He chortled in his joy.

’Twas brillig, and the slithy toves
      Did gyre and gimble in the wabe:
All mimsy were the borogoves,
      And the mome raths outgrabe.
snowy@merlin:~/argon$ bin/argonise decrypt Jabberwocky.txt 
DecryptText: Text does not appear to be Argon encrypted
snowy@merlin:~/argon$ bin/argonise encrypt Jabberwocky.txt 
snowy@merlin:~/argon$ bin/argonise encrypt Jabberwocky.txt 
EncryptText: Text is already Argon encrypted
snowy@merlin:~/argon$ bin/argonise decrypt Jabberwocky.txt 
snowy@merlin:~/argon$ 
```

