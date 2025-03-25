package engine

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"sync"
	"testing"

	"github.com/checkmarx/2ms/engine/rules"
	"github.com/checkmarx/2ms/lib/secrets"
	"github.com/checkmarx/2ms/plugins"
)

var fsPlugin = &plugins.FileSystemPlugin{}

func Test_Init(t *testing.T) {
	allRules := *rules.FilterRules([]string{}, []string{}, []string{})
	specialRule := rules.HardcodedPassword()

	tests := []struct {
		name         string
		engineConfig EngineConfig
		expectedErr  error
	}{
		{
			name: "selected and ignore flags used together for the same rule",
			engineConfig: EngineConfig{
				SelectedList: []string{allRules[0].Rule.RuleID},
				IgnoreList:   []string{allRules[0].Rule.RuleID},
				SpecialList:  []string{},
			},
			expectedErr: fmt.Errorf("no rules were selected"),
		},
		{
			name: "non existent select flag",
			engineConfig: EngineConfig{
				SelectedList: []string{"non-existent-tag-name"},
				IgnoreList:   []string{},
				SpecialList:  []string{"non-existent-tag-name"},
			},
			expectedErr: fmt.Errorf("no rules were selected"),
		},
		{
			name: "exiting special rule",
			engineConfig: EngineConfig{
				SelectedList: []string{"non-existent-tag-name"},
				IgnoreList:   []string{},
				SpecialList:  []string{specialRule.RuleID},
			},
			expectedErr: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Init(test.engineConfig)
			if err == nil && test.expectedErr != nil {
				t.Errorf("expected error, got nil")
			}
			if err != nil && err.Error() != test.expectedErr.Error() {
				t.Errorf("expected error: %s, got: %s", test.expectedErr.Error(), err.Error())
			}
		})
	}
}

func TestDetector(t *testing.T) {
	t.Run("ignore go.sum file", func(t *testing.T) {
		token := "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"
		i := item{
			content: &token,
			source:  "path/to/go.sum",
		}

		detector, err := Init(EngineConfig{})
		if err != nil {
			t.Fatal(err)
		}

		secretsChan := make(chan *secrets.Secret, 1)
		errorsChan := make(chan error, 1)
		wg := &sync.WaitGroup{}
		wg.Add(1)
		detector.Detect(i, secretsChan, wg, fsPlugin.GetName(), errorsChan)
		close(secretsChan)

		s := <-secretsChan
		if s != nil {
			t.Error("expected nil, got secret")
		}
	})
}

func TestSecrets(t *testing.T) {
	secretsCases := []struct {
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

	detector, err := Init(EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}

	for _, secret := range secretsCases {
		name := secret.Name
		if name == "" {
			name = secret.Content
		}
		t.Run(name, func(t *testing.T) {
			fmt.Printf("Start test %s", name)
			secretsChan := make(chan *secrets.Secret, 1)
			errorsChan := make(chan error, 1)
			wg := &sync.WaitGroup{}
			wg.Add(1)
			detector.Detect(item{content: &secret.Content}, secretsChan, wg, fsPlugin.GetName(), errorsChan)
			close(secretsChan)
			close(errorsChan)

			s := <-secretsChan

			if secret.ShouldFind {
				assert.Equal(t, s.LineContent, secret.Content)
			} else {
				assert.Nil(t, s)
			}
		})
	}
}

type item struct {
	content *string
	id      string
	source  string
}

var _ plugins.ISourceItem = (*item)(nil)

func (i item) GetContent() *string {
	return i.content
}
func (i item) GetID() string {
	if i.id != "" {
		return i.id
	}
	return "test"
}
func (i item) GetSource() string {
	if i.source != "" {
		return i.source
	}
	return "test"
}
