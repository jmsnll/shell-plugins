package age

import (
	"context"
	"fmt"

	"github.com/1Password/shell-plugins/sdk"
	"github.com/1Password/shell-plugins/sdk/provision"
)

type KeyFiles struct {
	private provision.ItemToFileContents
	public  provision.ItemToFileContents
}

type KeyPairProvisioner struct {
	keys        KeyFiles
	fileOptions []provision.FileOption
}

func (p KeyPairProvisioner) Provision(ctx context.Context, in sdk.ProvisionInput, out *sdk.ProvisionOutput) {
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

func (p KeyPairProvisioner) Deprovision(ctx context.Context, in sdk.DeprovisionInput, out *sdk.DeprovisionOutput) {
	// Nothing to do here: environment variables get wiped automatically when the process exits.
}

func (p KeyPairProvisioner) Description() string {
	return "Provision temporary file with public & private key pair & pass to age command"
}

func TempFile(keys KeyFiles, opts ...provision.FileOption) sdk.Provisioner {
	return KeyPairProvisioner{
		keys:        keys,
		fileOptions: opts,
	}
}
