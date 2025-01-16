package provisioner

import (
	"context"
	"github.com/1Password/shell-plugins/sdk"
	"github.com/1Password/shell-plugins/sdk/provision"
)

// PrivateKeyProvisioner handles the provisioning and deprovisioning of key files for the age command.
type PrivateKeyProvisioner struct {
	privateKey  provision.ItemToFileContents
	fileOptions []provision.FileOption
}

// Provision sets up the necessary key file for the `age` command based on the operation mode (Encrypt or Decrypt).
// It determines the mode from the command line arguments and prepares the corresponding key file.
func (p PrivateKeyProvisioner) Provision(ctx context.Context, in sdk.ProvisionInput, out *sdk.ProvisionOutput) {
	for _, arg := range out.CommandLine {
		if arg == "-i" || arg == "--identity" {
			out.AddError(ErrConflictingIdentityFlag)
		}
	}

	fileProvisioner := provision.TempFile(p.privateKey, p.fileOptions...)
	fileProvisioner.Provision(ctx, in, out)
}

// Deprovision performs cleanup after the process completes.
// In this implementation, no cleanup is required as temporary files are automatically removed.
func (p PrivateKeyProvisioner) Deprovision(ctx context.Context, in sdk.DeprovisionInput, out *sdk.DeprovisionOutput) {
}

func (p PrivateKeyProvisioner) Description() string {
	return "Provision temporary file with public & private key pair & pass to age command"
}

// PrivateKeyTempFile creates a new PrivateKeyProvisioner for handling temporary files for the age command.
func PrivateKeyTempFile(privateKey provision.ItemToFileContents, opts ...provision.FileOption) PrivateKeyProvisioner {
	opts = append(opts, provision.Filename("age.private.txt"), provision.PrependArgs("-i", "{{.Path}}"))
	return PrivateKeyProvisioner{
		privateKey:  privateKey,
		fileOptions: opts,
	}
}
