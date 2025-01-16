package provisioner

import (
	"context"
	"github.com/1Password/shell-plugins/sdk"
	"github.com/1Password/shell-plugins/sdk/provision"
)

// RecipientsProvisioner handles the provisioning and deprovisioning of key files for the age command.
type RecipientsProvisioner struct {
	publicKey   provision.ItemToFileContents
	fileOptions []provision.FileOption
}

// Provision sets up the necessary key file for the `age` command based on the operation mode (Encrypt or Decrypt).
// It determines the mode from the command line arguments and prepares the corresponding key file.
func (p RecipientsProvisioner) Provision(ctx context.Context, in sdk.ProvisionInput, out *sdk.ProvisionOutput) {
	fileProvisioner := provision.TempFile(p.publicKey, p.fileOptions...)
	fileProvisioner.Provision(ctx, in, out)
}

// Deprovision performs cleanup after the process completes.
// In this implementation, no cleanup is required as temporary files are automatically removed.
func (p RecipientsProvisioner) Deprovision(ctx context.Context, in sdk.DeprovisionInput, out *sdk.DeprovisionOutput) {
}

func (p RecipientsProvisioner) Description() string {
	return "Provision temporary file with optional recipients."
}

// RecipientsTempFile creates a new RecipientsProvisioner for handling temporary files for the age command.
func RecipientsTempFile(recipientsFile provision.ItemToFileContents, opts ...provision.FileOption) RecipientsProvisioner {
	opts = append(opts, provision.Filename("age.recipients.txt"), provision.PrependArgs("-R", "{{.Path}}"))
	return RecipientsProvisioner{
		publicKey:   recipientsFile,
		fileOptions: opts,
	}
}
