package secrets

import (
	"fmt"
	"sync"
	"testing"

	"github.com/checkmarx/2ms/plugins"
	"github.com/checkmarx/2ms/reporting"
	"github.com/checkmarx/2ms/secrets/rules"
)

func Test_Init(t *testing.T) {
	allRules := *rules.FilterRules([]string{}, []string{}, []string{})
	specialRule := rules.HardcodedPassword()

	tests := []struct {
		name         string
		selectedList []string
		ignoreList   []string
		specialList  []string
		expectedErr  error
	}{
		{
			name:         "selected and ignore flags used together for the same rule",
			selectedList: []string{allRules[0].Rule.RuleID},
			ignoreList:   []string{allRules[0].Rule.RuleID},
			specialList:  []string{},
			expectedErr:  fmt.Errorf("no rules were selected"),
		},
		{
			name:         "non existent select flag",
			selectedList: []string{"non-existent-tag-name"},
			ignoreList:   []string{},
			specialList:  []string{"non-existent-tag-name"},
			expectedErr:  fmt.Errorf("no rules were selected"),
		},
		{
			name:         "exiting special rule",
			selectedList: []string{"non-existent-tag-name"},
			ignoreList:   []string{},
			specialList:  []string{specialRule.RuleID},
			expectedErr:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Init(test.selectedList, test.ignoreList, test.specialList)
			if err == nil && test.expectedErr != nil {
				t.Errorf("expected error, got nil")
			}
			if err != nil && err.Error() != test.expectedErr.Error() {
				t.Errorf("expected error: %s, got: %s", test.expectedErr.Error(), err.Error())
			}
		})
	}
}

func TestSecrets(t *testing.T) {
	secrets := []struct {
		Content    string
		Name       string
		ShouldFind bool
	}{
		{
			Content:    "",
			Name:       "empty",
			ShouldFind: false,
		},
		{
			Content:    "mongodb+srv://radar:mytoken@io.dbb.mongodb.net/?retryWrites=true&w=majority",
			Name:       "Authenticated URL",
			ShouldFind: true,
		},
		{
			Content:    "--output=https://elastic:bF21iC0bfTVXo3qhpJqTGs78@c22f5bc9787c4c268d3b069ad866bdc2.eu-central-1.aws.cloud.es.io:9243/tfs",
			Name:       "Authenticated URL",
			ShouldFind: true,
		},
		{
			Content:    "https://abc:123@google.com",
			Name:       "Basic Authenticated URL",
			ShouldFind: true,
		},
		{
			Content:    "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",
			Name:       "GitHub Personal Access Token",
			ShouldFind: true,
		},
		{
			Content: "AKCp8jRRiQSAbghbuZmHKZcaKGEqbAASGH2SAb3rxXJQsSq9dGga8gFXe6aHpcRmzuHxN6oaT",
			Name:    "JFROG Secret without keyword",
			// gitleaks is using "keywords" to identify the next literal after the keyword is a secret,
			// that is why we are not expecting to find this secret
			ShouldFind: false,
		},
		{
			Content:    "--set imagePullSecretJfrog.password=AKCp8kqqfQbYifrbyvqusjyk6N3QKprXTv9B8HTitLbJzXT1kW7dDticXTsJpCrbqtizAwK4D \\",
			Name:       "JFROG Secret with keyword (real example)",
			ShouldFind: true,
		},
		{
			Content:    "--docker-password=AKCp8kqX8yeKBTqgm2XExHsp8yVdJn6SAgQmS1nJMfMDmzxEqX74rUGhedaWu7Eovid3VsMwb",
			Name:       "JFROG Secret as kubectl argument",
			ShouldFind: true,
		},
	}

	detector, err := Init([]string{}, []string{}, []string{})
	if err != nil {
		t.Fatal(err)
	}

	for _, secret := range secrets {
		name := secret.Name
		if name == "" {
			name = secret.Content
		}
		t.Run(name, func(t *testing.T) {
			fmt.Printf("Start test %s", name)
			secretsChan := make(chan reporting.Secret, 1)
			wg := &sync.WaitGroup{}
			wg.Add(1)
			detector.Detect(plugins.Item{Content: secret.Content}, secretsChan, wg, nil)
			close(secretsChan)

			s := <-secretsChan
			if s.Value == "" && secret.ShouldFind {
				t.Errorf("secret \"%s\" not found", secret.Name)
			}
			if s.Value != "" && !secret.ShouldFind {
				t.Errorf("should not find")
			}
		})
	}

}
