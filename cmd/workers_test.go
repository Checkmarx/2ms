package cmd

import (
	"github.com/checkmarx/2ms/engine"
	"github.com/checkmarx/2ms/lib/reporting"
	"github.com/checkmarx/2ms/lib/secrets"
	"github.com/checkmarx/2ms/plugins"
	"github.com/stretchr/testify/assert"
	"sort"
	"strconv"
	"sync"
	"testing"
)

type mockItem struct {
	content *string
	id      string
	source  string
}

func (i *mockItem) GetContent() *string {
	return i.content
}

func (i *mockItem) GetID() string {
	return i.id
}

func (i *mockItem) GetSource() string {
	return i.source
}

func TestProcessItems(t *testing.T) {
	totalItemsToProcess := 5
	engineConfig := engine.EngineConfig{}
	engineTest, err := engine.Init(engineConfig)
	assert.NoError(t, err)
	report = reporting.Init()
	channels.Items = make(chan plugins.ISourceItem)
	channels.WaitGroup = &sync.WaitGroup{}
	channels.WaitGroup.Add(1)
	go processItems(engineTest, "mockPlugin")
	for i := 0; i < totalItemsToProcess; i++ {
		mockData := strconv.Itoa(i)
		channels.Items <- &mockItem{
			content: &mockData,
			id:      mockData,
		}
	}
	close(channels.Items)
	channels.WaitGroup.Wait()
	assert.Equal(t, totalItemsToProcess, report.TotalItemsScanned)
}

func TestProcessSecrets(t *testing.T) {
	tests := []struct {
		name        string
		validateVar bool
	}{
		{
			name:        "Validate flag is enabled",
			validateVar: true,
		},
		{
			name:        "Validate flag is disabled",
			validateVar: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report = reporting.Init()
			secretsChan = make(chan *secrets.Secret, 3)
			secretsExtrasChan = make(chan *secrets.Secret, 3)
			validationChan = make(chan *secrets.Secret, 3)
			cvssScoreWithoutValidationChan = make(chan *secrets.Secret, 3)
			channels.WaitGroup = &sync.WaitGroup{}
			validateVar = tt.validateVar
			secretsChan <- &secrets.Secret{ID: "mockId", StartLine: 1}
			secretsChan <- &secrets.Secret{ID: "mockId2"}
			secretsChan <- &secrets.Secret{ID: "mockId", StartLine: 2}
			close(secretsChan)

			channels.WaitGroup.Add(1)
			go processSecrets()

			channels.WaitGroup.Wait()

			expectedSecrets := []*secrets.Secret{
				{ID: "mockId", StartLine: 1},
				{ID: "mockId", StartLine: 2},
				{ID: "mockId2"},
			}
			var actualSecrets []*secrets.Secret
			for val := range secretsExtrasChan {
				actualSecrets = append(actualSecrets, val)
			}
			sort.Slice(actualSecrets, func(i, j int) bool {
				if actualSecrets[i].ID == actualSecrets[j].ID {
					return actualSecrets[i].StartLine < actualSecrets[j].StartLine
				}
				return actualSecrets[i].ID < actualSecrets[j].ID
			})
			assert.Equal(t, expectedSecrets, actualSecrets)

			if validateVar {
				assert.Empty(t, cvssScoreWithoutValidationChan)
				var actualSecretsWithValidation []*secrets.Secret
				for val := range validationChan {
					actualSecretsWithValidation = append(actualSecretsWithValidation, val)
				}
				sort.Slice(actualSecretsWithValidation, func(i, j int) bool {
					if actualSecretsWithValidation[i].ID == actualSecretsWithValidation[j].ID {
						return actualSecretsWithValidation[i].StartLine < actualSecretsWithValidation[j].StartLine
					}
					return actualSecretsWithValidation[i].ID < actualSecretsWithValidation[j].ID
				})
				assert.Equal(t, expectedSecrets, actualSecretsWithValidation)
			} else {
				assert.Empty(t, validationChan)
				var actualSecretsWithoutValidation []*secrets.Secret
				for val := range cvssScoreWithoutValidationChan {
					actualSecretsWithoutValidation = append(actualSecretsWithoutValidation, val)
				}
				sort.Slice(actualSecretsWithoutValidation, func(i, j int) bool {
					if actualSecretsWithoutValidation[i].ID == actualSecretsWithoutValidation[j].ID {
						return actualSecretsWithoutValidation[i].StartLine < actualSecretsWithoutValidation[j].StartLine
					}
					return actualSecretsWithoutValidation[i].ID < actualSecretsWithoutValidation[j].ID
				})
				assert.Equal(t, expectedSecrets, actualSecretsWithoutValidation)
			}

			assert.Equal(t, 3, report.TotalSecretsFound)
			assert.Equal(t, 2, len(report.Results["mockId"]))
			assert.Equal(t, 1, len(report.Results["mockId2"]))
			assert.Equal(t, &secrets.Secret{ID: "mockId", StartLine: 1}, report.Results["mockId"][0])
			assert.Equal(t, &secrets.Secret{ID: "mockId", StartLine: 2}, report.Results["mockId"][1])
			assert.Equal(t, &secrets.Secret{ID: "mockId2"}, report.Results["mockId2"][0])
		})
	}
}

func TestProcessSecretsExtras(t *testing.T) {
	tests := []struct {
		name            string
		inputSecrets    []*secrets.Secret
		expectedSecrets []*secrets.Secret
	}{
		{
			name: "Should update the extra details of secrets",
			inputSecrets: []*secrets.Secret{
				{
					ID:     "mockId",
					RuleID: "jwt",
					Value:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtb2NrU3ViMSIsIm5hbWUiOiJtb2NrTmFtZTEifQ.dummysignature1",
				},
				{
					ID:     "mockId2",
					RuleID: "jwt",
					Value:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtb2NrU3ViMiIsIm5hbWUiOiJtb2NrTmFtZTIifQ.dummysignature2",
				},
			},
			expectedSecrets: []*secrets.Secret{
				{
					ID:     "mockId",
					RuleID: "jwt",
					Value:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtb2NrU3ViMSIsIm5hbWUiOiJtb2NrTmFtZTEifQ.dummysignature1",
					ExtraDetails: map[string]interface{}{
						"secretDetails": map[string]interface{}{
							"sub":  "mockSub1",
							"name": "mockName1",
						},
					},
				},
				{
					ID:     "mockId2",
					RuleID: "jwt",
					Value:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtb2NrU3ViMiIsIm5hbWUiOiJtb2NrTmFtZTIifQ.dummysignature2",
					ExtraDetails: map[string]interface{}{
						"secretDetails": map[string]interface{}{
							"sub":  "mockSub2",
							"name": "mockName2",
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secretsExtrasChan = make(chan *secrets.Secret, len(tt.inputSecrets))
			for _, secret := range tt.inputSecrets {
				secretsExtrasChan <- secret
			}
			close(secretsExtrasChan)

			channels.WaitGroup.Add(1)
			go processSecretsExtras()
			channels.WaitGroup.Wait()

			for i, expected := range tt.expectedSecrets {
				assert.Equal(t, expected, tt.inputSecrets[i])
			}
		})
	}
}

func TestProcessValidationAndScoreWithValidation(t *testing.T) {
	tests := []struct {
		name            string
		inputSecrets    []*secrets.Secret
		expectedSecrets []*secrets.Secret
	}{
		{
			name: "Should update validationStatus and CvssScore of secrets",
			inputSecrets: []*secrets.Secret{
				{
					ID:     "mockId",
					RuleID: "github-pat",
					Value:  "ghp_mockmockmockmockmockmockmockmockmock",
				},
				{
					ID:     "mockId2",
					RuleID: "github-pat",
					Value:  "ghp_mockmockmockmockmockmockmockmockmocj",
				},
			},
			expectedSecrets: []*secrets.Secret{
				{
					ID:               "mockId",
					RuleID:           "github-pat",
					Value:            "ghp_mockmockmockmockmockmockmockmockmock",
					ValidationStatus: "Invalid",
					CvssScore:        5.2,
				},
				{
					ID:               "mockId2",
					RuleID:           "github-pat",
					Value:            "ghp_mockmockmockmockmockmockmockmockmocj",
					ValidationStatus: "Invalid",
					CvssScore:        5.2,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engineConfig := engine.EngineConfig{}
			engineTest, err := engine.Init(engineConfig)
			assert.NoError(t, err)
			validationChan = make(chan *secrets.Secret, len(tt.inputSecrets))
			for _, secret := range tt.inputSecrets {
				validationChan <- secret
			}
			close(validationChan)

			channels.WaitGroup.Add(1)
			go processValidationAndScoreWithValidation(engineTest)
			channels.WaitGroup.Wait()

			for i, expected := range tt.expectedSecrets {
				assert.Equal(t, expected, tt.inputSecrets[i])
			}
		})
	}
}

func TestProcessScoreWithoutValidation(t *testing.T) {
	tests := []struct {
		name            string
		inputSecrets    []*secrets.Secret
		expectedSecrets []*secrets.Secret
	}{
		{
			name: "Should update CvssScore of secrets",
			inputSecrets: []*secrets.Secret{
				{
					ID:     "mockId",
					RuleID: "github-pat",
					Value:  "ghp_mockmockmockmockmockmockmockmockmock",
				},
				{
					ID:     "mockId2",
					RuleID: "github-pat",
					Value:  "ghp_mockmockmockmockmockmockmockmockmocj",
				},
			},
			expectedSecrets: []*secrets.Secret{
				{
					ID:               "mockId",
					RuleID:           "github-pat",
					Value:            "ghp_mockmockmockmockmockmockmockmockmock",
					ValidationStatus: "",
					CvssScore:        8.2,
				},
				{
					ID:               "mockId2",
					RuleID:           "github-pat",
					Value:            "ghp_mockmockmockmockmockmockmockmockmocj",
					ValidationStatus: "",
					CvssScore:        8.2,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engineConfig := engine.EngineConfig{}
			engineTest, err := engine.Init(engineConfig)
			assert.NoError(t, err)
			cvssScoreWithoutValidationChan = make(chan *secrets.Secret, len(tt.inputSecrets))
			for _, secret := range tt.inputSecrets {
				cvssScoreWithoutValidationChan <- secret
			}
			close(cvssScoreWithoutValidationChan)

			channels.WaitGroup.Add(1)
			go processScoreWithoutValidation(engineTest)
			channels.WaitGroup.Wait()

			for i, expected := range tt.expectedSecrets {
				assert.Equal(t, expected, tt.inputSecrets[i])
			}
		})
	}
}
