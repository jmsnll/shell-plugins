package age

import (
	"testing"

	"github.com/1Password/shell-plugins/sdk"
	"github.com/1Password/shell-plugins/sdk/plugintest"
	"github.com/1Password/shell-plugins/sdk/schema/fieldname"
)

func TestRecipientsProvisioner(t *testing.T) {
	plugintest.TestProvisioner(t, Recipients().DefaultProvisioner, map[string]plugintest.ProvisionCase{
		"defaults-to-encryption-mode": {
			ItemFields: map[sdk.FieldName]string{
				fieldname.Recipients: "age10000000000000000000000000000000000000000000000000000000000",
			},
			CommandLine: []string{"age", "-o", "/tmp/encrypted.txt", "/tmp/unencrypted.txt"},
			ExpectedOutput: sdk.ProvisionOutput{
				CommandLine: []string{"age", "-R", "/tmp/age.recipients.txt", "-o", "/tmp/encrypted.txt", "/tmp/unencrypted.txt"},
				Files: map[string]sdk.OutputFile{
					"/tmp/age.recipients.txt": {
						Contents: []byte(plugintest.LoadFixture(t, "age.recipients.txt")),
					},
				},
			},
		},
		"explicit-encryption-mode-short": {
			ItemFields: map[sdk.FieldName]string{
				fieldname.Recipients: "age10000000000000000000000000000000000000000000000000000000000",
			},
			CommandLine: []string{"age", "-e", "-o", "/tmp/encrypted.txt", "/tmp/unencrypted.txt"},
			ExpectedOutput: sdk.ProvisionOutput{
				CommandLine: []string{"age", "-R", "/tmp/age.recipients.txt", "-e", "-o", "/tmp/encrypted.txt", "/tmp/unencrypted.txt"},
				Files: map[string]sdk.OutputFile{
					"/tmp/age.recipients.txt": {
						Contents: []byte(plugintest.LoadFixture(t, "age.recipients.txt")),
					},
				},
			},
		},
		"explicit-encryption-mode-long": {
			ItemFields: map[sdk.FieldName]string{
				fieldname.Recipients: "age10000000000000000000000000000000000000000000000000000000000",
			},
			CommandLine: []string{"age", "--encrypt", "-o", "/tmp/encrypted.txt", "/tmp/unencrypted.txt"},
			ExpectedOutput: sdk.ProvisionOutput{
				CommandLine: []string{"age", "-R", "/tmp/age.recipients.txt", "--encrypt", "-o", "/tmp/encrypted.txt", "/tmp/unencrypted.txt"},
				Files: map[string]sdk.OutputFile{
					"/tmp/age.recipients.txt": {
						Contents: []byte(plugintest.LoadFixture(t, "age.recipients.txt")),
					},
				},
			},
		},
		"decryption-mode-short": {
			ItemFields: map[sdk.FieldName]string{
				fieldname.Recipients: "age10000000000000000000000000000000000000000000000000000000000",
			},
			CommandLine: []string{"age", "-d", "-o", "/tmp/encrypted.txt", "/tmp/unencrypted.txt"},
			ExpectedOutput: sdk.ProvisionOutput{
				CommandLine: []string{"age", "-d", "-o", "/tmp/encrypted.txt", "/tmp/unencrypted.txt"},
				Files:       map[string]sdk.OutputFile{},
			},
		},
		"decryption-mode-long": {
			ItemFields: map[sdk.FieldName]string{
				fieldname.Recipients: "age10000000000000000000000000000000000000000000000000000000000",
			},
			CommandLine: []string{"age", "--decrypt", "-o", "/tmp/encrypted.txt", "/tmp/unencrypted.txt"},
			ExpectedOutput: sdk.ProvisionOutput{
				CommandLine: []string{"age", "--decrypt", "-o", "/tmp/encrypted.txt", "/tmp/unencrypted.txt"},
				Files:       map[string]sdk.OutputFile{},
			},
		},
	})
}
