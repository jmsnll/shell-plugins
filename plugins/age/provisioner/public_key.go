package provisioner

import (
	"context"
	"github.com/1Password/shell-plugins/sdk"
	"github.com/1Password/shell-plugins/sdk/provision"
)

// PublicKeyProvisioner handles the provisioning and deprovisioning of key files for the age command.
type PublicKeyProvisioner struct {
	publicKey   provision.ItemToFileContents
	fileOptions []provision.FileOption
}

// Provision sets up the necessary key file for the `age` command based on the operation mode (Encrypt or Decrypt).
// It determines the mode from the command line arguments and prepares the corresponding key file.
func (p PublicKeyProvisioner) Provision(ctx context.Context, in sdk.ProvisionInput, out *sdk.ProvisionOutput) {
	fileProvisioner := provision.TempFile(p.publicKey, p.fileOptions...)
	fileProvisioner.Provision(ctx, in, out)
}

// Deprovision performs cleanup after the process completes.
// In this implementation, no cleanup is required as temporary files are automatically removed.
func (p PublicKeyProvisioner) Deprovision(ctx context.Context, in sdk.DeprovisionInput, out *sdk.DeprovisionOutput) {
}

func (p PublicKeyProvisioner) Description() string {
	return "Provision temporary file with public & private key pair & pass to age command"
}

// PublicKeyTempFile creates a new PublicKeyProvisioner for handling temporary files for the age command.
func PublicKeyTempFile(publicKey provision.ItemToFileContents, opts ...provision.FileOption) PublicKeyProvisioner {
	opts = append(opts, provision.Filename("age.private.txt"), provision.PrependArgs("-R", "{{.Path}}"))
	return PublicKeyProvisioner{
		publicKey:   publicKey,
		fileOptions: opts,
	}
}
