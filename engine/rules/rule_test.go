package rules_test

import (
	"testing"

	"github.com/checkmarx/2ms/engine/rules"
	"github.com/zricethezav/gitleaks/v8/config"
)

func Test2msRules(t *testing.T) {
	t.Parallel()

	testsRules := []struct {
		name     string
		validate func() *config.Rule
	}{
		{name: "AuthenticatedURL", validate: rules.AuthenticatedURL},
		{name: "Clojars", validate: rules.Clojars},
		{name: "GenericCredential", validate: rules.GenericCredential},
		{name: "GitHubApp", validate: rules.GitHubApp},
		{name: "HardcodedPassword", validate: rules.HardcodedPassword},
		{name: "PlaidAccessID", validate: rules.PlaidAccessID},
		{name: "PrivateKey", validate: rules.PrivateKey},
		{name: "VaultServiceToken", validate: rules.VaultServiceToken},
	}

	for _, tRule := range testsRules {
		testRule := tRule // fix for loop variable being captured by func literal
		t.Run(testRule.name, func(t *testing.T) {
			t.Parallel()

			testRule.validate()
		})
	}
}
