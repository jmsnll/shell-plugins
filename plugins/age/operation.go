package age

const (
	decryptShort = "-d"
	decryptLong  = "--decrypt"
	encryptShort = "-e"
	encryptLong  = "--encrypt"
)

type Operation int

const (
	Encrypt Operation = iota
	Decrypt
)

func detectOperation(args []string) Operation {
	for _, arg := range args {
		switch arg {
		case decryptShort, decryptLong:
			return Decrypt
		case encryptShort, encryptLong:
			return Encrypt
		}
	}
	return Encrypt
}
