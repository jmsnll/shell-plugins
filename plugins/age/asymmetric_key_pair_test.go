package age

import (
	"testing"

	"github.com/1Password/shell-plugins/sdk"
	"github.com/1Password/shell-plugins/sdk/plugintest"
	"github.com/1Password/shell-plugins/sdk/schema/fieldname"
)

func TestAsymmetricKeyPairProvisioner(t *testing.T) {
	plugintest.TestProvisioner(t, AsymmetricKeyPair().DefaultProvisioner, map[string]plugintest.ProvisionCase{
		"default": {
			ItemFields: map[sdk.FieldName]string{ // TODO: Check if this is correct
				fieldname.PrivateKey: "AGE-SECRET-KEY-10000000000000000000000000000000000000000000000000000000000",
				fieldname.PublicKey:  "age10000000000000000000000000000000000000000000000000000000000",
			},
			CommandLine: []string{"age"},
			ExpectedOutput: sdk.ProvisionOutput{
				CommandLine: []string{"age", "--identity=/tmp/age.txt"},
				Files: map[string]sdk.OutputFile{
					"/tmp/age.txt": {
						Contents: []byte(plugintest.LoadFixture(t, "age.default.txt")),
					},
				},
			},
		},
		"with-args": {
			ItemFields: map[sdk.FieldName]string{ // TODO: Check if this is correct
				fieldname.PrivateKey: "AGE-SECRET-KEY-10000000000000000000000000000000000000000000000000000000000",
				fieldname.PublicKey:  "age10000000000000000000000000000000000000000000000000000000000",
			},
			CommandLine: []string{"age"},
			ExpectedOutput: sdk.ProvisionOutput{
				CommandLine: []string{"age", "--identity=/tmp/age.txt"},
				Files: map[string]sdk.OutputFile{
					"/tmp/age.txt": {
						Contents: []byte(plugintest.LoadFixture(t, "age.default.txt")),
					},
				},
			},
		},
	})
}

func TestAsymmetricKeyPairImporter(t *testing.T) {
	plugintest.TestImporter(t, AsymmetricKeyPair().Importer, map[string]plugintest.ImportCase{
		"environment": {
			Environment: map[string]string{ // TODO: Check if this is correct
				"AGE_KEY": "RQFYZXCY9K3GE3Q0T2GLXLN5JUBEUTHWDYIJF3A831L9L2YG91MQKVP805RZPRRGZLSEXAMPLE",
			},
			ExpectedCandidates: []sdk.ImportCandidate{
				{
					Fields: map[sdk.FieldName]string{
						fieldname.Key: "RQFYZXCY9K3GE3Q0T2GLXLN5JUBEUTHWDYIJF3A831L9L2YG91MQKVP805RZPRRGZLSEXAMPLE",
					},
				},
			},
		},
		// TODO: If you implemented a config file importer, add a test file example in age/test-fixtures
		// and fill the necessary details in the test template below.
		"config file": {
			Files: map[string]string{
				// "~/path/to/config.yml": plugintest.LoadFixture(t, "config.yml"),
			},
			ExpectedCandidates: []sdk.ImportCandidate{
				// 	{
				// 		Fields: map[sdk.FieldName]string{
				// 			fieldname.Token: "RQFYZXCY9K3GE3Q0T2GLXLN5JUBEUTHWDYIJF3A831L9L2YG91MQKVP805RZPRRGZLSEXAMPLE",
				// 		},
				// 	},
			},
		},
	})
}
