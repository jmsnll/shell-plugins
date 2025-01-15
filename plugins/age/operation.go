package age

const (
	decryptShort = "-d"
	decryptLong  = "--decrypt"
	encryptShort = "-e"
	encryptLong  = "--encrypt"
)

const (
	Encrypt Operation = iota
	Decrypt
)

type Operation int

func (op Operation) String() string {
	switch op {
	case Encrypt:
		return "encrypt"
	case Decrypt:
		return "decrypt"
	default:
		return "unknown"
	}
}

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
