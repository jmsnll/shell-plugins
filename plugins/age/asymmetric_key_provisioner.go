package age

import (
	"context"
	"fmt"
	"github.com/1Password/shell-plugins/sdk"
	"github.com/1Password/shell-plugins/sdk/provision"
)

type AsymmetricKeyProvisioner struct {
	keys        KeyFiles
	fileOptions []provision.FileOption
}

type KeyFiles struct {
	private provision.ItemToFileContents
	public  provision.ItemToFileContents
}

// TempFile returns a file provisioner and takes a function that maps a 1Password item to the contents of
// a single file.
func TempFile(keys KeyFiles, opts ...provision.FileOption) sdk.Provisioner {
	return AsymmetricKeyProvisioner{
		keys:        keys,
		fileOptions: opts,
	}
}

func (o Operation) String() string {
	switch o {
	case Encrypt:
		return "Encrypt"
	case Decrypt:
		return "Decrypt"
	}
	return "Unknown"
}

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

func (p AsymmetricKeyProvisioner) Provision(ctx context.Context, in sdk.ProvisionInput, out *sdk.ProvisionOutput) {
	mode := detectOperation(out.CommandLine)

	var keyFileMaterialiser provision.ItemToFileContents
	var args []string
	var filename string

	switch mode {
	case Encrypt:
		keyFileMaterialiser = p.keys.public
		args = []string{"-R", "{{.Path}}"}
		filename = "age.public.txt"
	case Decrypt:
		keyFileMaterialiser = p.keys.private
		args = []string{"-i", "{{.Path}}"}
		filename = "age.private.txt"
	default:
		out.AddError(fmt.Errorf("unknown command: %s", mode))
		return
	}

	p.fileOptions = append(p.fileOptions, provision.Filename(filename), provision.AddArgs(provision.ArgPlacement{Mode: provision.AtStart}, args...))
	fileProvisioner := provision.TempFile(keyFileMaterialiser, p.fileOptions...)
	fileProvisioner.Provision(ctx, in, out)
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

func (p AsymmetricKeyProvisioner) Deprovision(ctx context.Context, in sdk.DeprovisionInput, out *sdk.DeprovisionOutput) {
	// Nothing to do here: environment variables get wiped automatically when the process exits.
}

func (p AsymmetricKeyProvisioner) Description() string {
	return "Provision temporary file with public & private key pair & pass to age command"
}
