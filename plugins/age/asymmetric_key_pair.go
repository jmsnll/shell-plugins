package age

import (
	"fmt"
	"github.com/1Password/shell-plugins/sdk"
	"github.com/1Password/shell-plugins/sdk/importer"
	"github.com/1Password/shell-plugins/sdk/provision"
	"github.com/1Password/shell-plugins/sdk/schema"
	"github.com/1Password/shell-plugins/sdk/schema/credname"
	"github.com/1Password/shell-plugins/sdk/schema/fieldname"
)

func AsymmetricKeyPair() schema.CredentialType {
	return schema.CredentialType{
		Name:          credname.SecretKey,
		DocsURL:       sdk.URL("https://age.com/docs/secret_key"),              // TODO: Replace with actual URL
		ManagementURL: sdk.URL("https://console.age.com/user/security/tokens"), // TODO: Replace with actual URL
		Fields: []schema.CredentialField{
			{
				Name:                fieldname.PublicKey,
				MarkdownDescription: "Age public key.",
				Secret:              false,
				Composition: &schema.ValueComposition{
					Length: 63,
					Charset: schema.Charset{
						Lowercase: true,
						Digits:    true,
					},
				},
			},
			{
				Name:                fieldname.PrivateKey,
				MarkdownDescription: "Age private key.",
				Secret:              true,
				Composition: &schema.ValueComposition{
					Length: 75,
					Charset: schema.Charset{
						Uppercase: true,
						Digits:    true,
						Specific:  []rune{'-'},
					},
				},
			},
		},
		DefaultProvisioner: provision.TempFile(ageKey, provision.Filename("age.txt"), provision.AddArgs(provision.ArgPlacement{Mode: provision.AtStart}, "--identity={{ .Path }}")),
		Importer:           importer.NoOp(),
	}
}

func ageKey(in sdk.ProvisionInput) ([]byte, error) {
	content := ""

	if publicKey, ok := in.ItemFields[fieldname.PublicKey]; ok {
		content += fmt.Sprintf("# public key: %s\n", publicKey)
	}

	if privateKey, ok := in.ItemFields[fieldname.PrivateKey]; ok {
		content += fmt.Sprintf("%s", privateKey)
	}

	return []byte(content), nil
}
