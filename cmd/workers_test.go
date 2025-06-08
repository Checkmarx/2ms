package cmd

import (
	"github.com/checkmarx/2ms/v3/engine"
	"github.com/checkmarx/2ms/v3/lib/reporting"
	"github.com/checkmarx/2ms/v3/lib/secrets"
	"github.com/checkmarx/2ms/v3/plugins"
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

func (i *mockItem) GetGitInfo() *plugins.GitInfo {
	return nil
}

func TestProcessItems(t *testing.T) {
	totalItemsToProcess := 5
	engineConfig := engine.EngineConfig{}
	engineTest, err := engine.Init(engineConfig)
	assert.NoError(t, err)
	Report = reporting.Init()
	Channels.Items = make(chan plugins.ISourceItem)
	SecretsChan = make(chan *secrets.Secret)
	Channels.WaitGroup = &sync.WaitGroup{}
	Channels.WaitGroup.Add(1)
	go ProcessItems(engineTest, "mockPlugin")
	for i := 0; i < totalItemsToProcess; i++ {
		mockData := strconv.Itoa(i)
		Channels.Items <- &mockItem{
			content: &mockData,
			id:      mockData,
		}
	}
	close(Channels.Items)
	Channels.WaitGroup.Wait()
	assert.Equal(t, totalItemsToProcess, Report.TotalItemsScanned)
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
			Report = reporting.Init()
			SecretsChan = make(chan *secrets.Secret, 3)
			SecretsExtrasChan = make(chan *secrets.Secret, 3)
			ValidationChan = make(chan *secrets.Secret, 3)
			CvssScoreWithoutValidationChan = make(chan *secrets.Secret, 3)
			Channels.WaitGroup = &sync.WaitGroup{}
			validateVar = tt.validateVar
			SecretsChan <- &secrets.Secret{ID: "mockId", StartLine: 1}
			SecretsChan <- &secrets.Secret{ID: "mockId2"}
			SecretsChan <- &secrets.Secret{ID: "mockId", StartLine: 2}
			close(SecretsChan)

			Channels.WaitGroup.Add(1)
			go ProcessSecrets()

			Channels.WaitGroup.Wait()

			expectedSecrets := []*secrets.Secret{
				{ID: "mockId", StartLine: 1},
				{ID: "mockId", StartLine: 2},
				{ID: "mockId2"},
			}
			var actualSecrets []*secrets.Secret
			for val := range SecretsExtrasChan {
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
				assert.Empty(t, CvssScoreWithoutValidationChan)
				var actualSecretsWithValidation []*secrets.Secret
				for val := range ValidationChan {
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
				assert.Empty(t, ValidationChan)
				var actualSecretsWithoutValidation []*secrets.Secret
				for val := range CvssScoreWithoutValidationChan {
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

			assert.Equal(t, 3, Report.TotalSecretsFound)
			assert.Equal(t, 2, len(Report.Results["mockId"]))
			assert.Equal(t, 1, len(Report.Results["mockId2"]))
			assert.Equal(t, &secrets.Secret{ID: "mockId", StartLine: 1}, Report.Results["mockId"][0])
			assert.Equal(t, &secrets.Secret{ID: "mockId", StartLine: 2}, Report.Results["mockId"][1])
			assert.Equal(t, &secrets.Secret{ID: "mockId2"}, Report.Results["mockId2"][0])
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
			SecretsExtrasChan = make(chan *secrets.Secret, len(tt.inputSecrets))
			for _, secret := range tt.inputSecrets {
				SecretsExtrasChan <- secret
			}
			close(SecretsExtrasChan)

			Channels.WaitGroup.Add(1)
			go ProcessSecretsExtras()
			Channels.WaitGroup.Wait()

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
			ValidationChan = make(chan *secrets.Secret, len(tt.inputSecrets))
			for _, secret := range tt.inputSecrets {
				ValidationChan <- secret
			}
			close(ValidationChan)

			Channels.WaitGroup.Add(1)
			go ProcessValidationAndScoreWithValidation(engineTest)
			Channels.WaitGroup.Wait()

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
			CvssScoreWithoutValidationChan = make(chan *secrets.Secret, len(tt.inputSecrets))
			for _, secret := range tt.inputSecrets {
				CvssScoreWithoutValidationChan <- secret
			}
			close(CvssScoreWithoutValidationChan)

			Channels.WaitGroup.Add(1)
			go ProcessScoreWithoutValidation(engineTest)
			Channels.WaitGroup.Wait()

			for i, expected := range tt.expectedSecrets {
				assert.Equal(t, expected, tt.inputSecrets[i])
			}
		})
	}
}
