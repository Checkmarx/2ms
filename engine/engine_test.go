package engine

//go:generate mockgen -destination=plugins_mock_test.go -package=${GOPACKAGE} github.com/checkmarx/2ms/v4/plugins ISourceItem

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"go.uber.org/mock/gomock"

	"github.com/checkmarx/2ms/v4/engine/chunk"
	"github.com/checkmarx/2ms/v4/engine/rules"
	"github.com/checkmarx/2ms/v4/engine/semaphore"
	"github.com/checkmarx/2ms/v4/internal/resources"
	"github.com/checkmarx/2ms/v4/lib/secrets"
	"github.com/checkmarx/2ms/v4/plugins"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

// Removed global fsPlugin to avoid test interference

type mock struct {
	semaphore *semaphore.MockISemaphore
	chunk     *chunk.MockIChunk
}

func newMock(ctrl *gomock.Controller) *mock {
	return &mock{
		semaphore: semaphore.NewMockISemaphore(ctrl),
		chunk:     chunk.NewMockIChunk(ctrl),
	}
}

func Test_Init(t *testing.T) {
	allRules := rules.FilterRules([]string{}, []string{}, []string{})
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
			expectedErr: ErrNoRulesSelected,
		},
		{
			name: "non existent select flag",
			engineConfig: EngineConfig{
				SelectedList: []string{"non-existent-tag-name"},
				IgnoreList:   []string{},
				SpecialList:  []string{"non-existent-tag-name"},
			},
			expectedErr: ErrNoRulesSelected,
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
			_, err := Init(&test.engineConfig)
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

		eng, err := initEngine(&EngineConfig{
			DetectorWorkerPoolSize: 1,
		})
		require.NoError(t, err)
		require.NotNil(t, eng)

		secretsChan := make(chan *secrets.Secret, 1)
		fsPlugin := &plugins.FileSystemPlugin{}
		err = eng.DetectFragment(i, secretsChan, fsPlugin.GetName())
		assert.NoError(t, err)

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
		{
			Content:    "\"a_b_key\": \"x-someval-127.0.0.1\",",
			Name:       "Generic Api Key",
			ShouldFind: false,
		},
		{
			Content:    "KeyVaultSecretsUser: '62168719-64c5-453d-b4ef-b51d8b1ad44d'",
			Name:       "Generic Api Key",
			ShouldFind: false,
		},
		{
			Content:    "SecretKey: \n\t\t\t              'NzFEUDg0Y0Jtc25sbko4VU96Q3VxM184bGkxV2xEb0twajY3ZFVybEtrcj0=',",
			Name:       "Generic Api Key",
			ShouldFind: true,
		},
	}

	detector, err := initEngine(&EngineConfig{
		DetectorWorkerPoolSize: 1,
	})
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
			fsPlugin := &plugins.FileSystemPlugin{}
			err = detector.DetectFragment(item{content: &secret.Content}, secretsChan, fsPlugin.GetName())
			if err != nil {
				return
			}
			close(secretsChan)

			s := <-secretsChan

			if secret.ShouldFind {
				assert.Equal(t, s.LineContent, secret.Content)
			} else {
				assert.Nil(t, s)
			}
		})
	}
}

func TestDetectFile(t *testing.T) {
	fileSize := 10
	sizeThreshold := int64(20)
	chunkSize := 5
	maxPeekSize := 10
	chunkWeight := int64(4*chunkSize + 2*maxPeekSize) // 40 bytes

	testCases := []struct {
		name         string
		makeFile     func(tmp string) string
		mockFunc     func(m *mock)
		maxMegabytes int
		memoryBudget int64
		expectedLog  string
		expectedErr  error
	}{
		{
			name:         "non existent file",
			makeFile:     func(tmp string) string { return filepath.Join(tmp, "does-not-exist") },
			mockFunc:     func(m *mock) {},
			memoryBudget: 1_000,
			expectedErr:  fmt.Errorf("failed to stat"),
		},
		{
			name:         "exceed max megabytes",
			makeFile:     func(tmp string) string { return writeTempFile(t, tmp, 2000000, nil) /* 2MB */ },
			mockFunc:     func(m *mock) {},
			maxMegabytes: 1,
			memoryBudget: 1_000,
		},
		{
			name:     "small file - acquire error",
			makeFile: func(tmp string) string { return writeTempFile(t, tmp, fileSize, nil) },
			mockFunc: func(m *mock) {
				weight := int64(fileSize * 2)
				m.chunk.EXPECT().GetFileThreshold().Return(sizeThreshold)
				m.semaphore.EXPECT().AcquireMemoryWeight(gomock.Any(), weight).Return(assert.AnError)
			},
			memoryBudget: int64(fileSize*2) - 1, // 19 bytes < 2*filesize = 20 bytes
			expectedErr:  assert.AnError,
		},
		{
			name:     "small file - success & release",
			makeFile: func(tmp string) string { return writeTempFile(t, tmp, fileSize, nil) },
			mockFunc: func(m *mock) {
				weight := int64(fileSize * 2)
				m.chunk.EXPECT().GetFileThreshold().Return(sizeThreshold)
				m.semaphore.EXPECT().AcquireMemoryWeight(gomock.Any(), weight).Return(nil)
				m.semaphore.EXPECT().ReleaseMemoryWeight(weight)
			},
			memoryBudget: 1_000,
		},
		{
			name:     "large file - acquire error",
			makeFile: func(tmp string) string { return writeTempFile(t, tmp, fileSize*2+1, nil) },
			mockFunc: func(m *mock) {
				m.chunk.EXPECT().GetFileThreshold().Return(sizeThreshold)
				m.chunk.EXPECT().GetSize().Return(chunkSize)
				m.chunk.EXPECT().GetMaxPeekSize().Return(maxPeekSize)
				m.semaphore.EXPECT().AcquireMemoryWeight(gomock.Any(), chunkWeight).Return(assert.AnError)
			},
			memoryBudget: chunkWeight - 1, // 40 - 1 byte < 40 bytes
			expectedErr:  assert.AnError,
		},
		{
			name:     "large file - read chunk error",
			makeFile: func(tmp string) string { return writeTempFile(t, tmp, fileSize*2+1, nil) },
			mockFunc: func(m *mock) {
				m.chunk.EXPECT().GetFileThreshold().Return(sizeThreshold)
				m.chunk.EXPECT().GetSize().Return(chunkSize)
				m.chunk.EXPECT().GetMaxPeekSize().Return(maxPeekSize)
				m.semaphore.EXPECT().AcquireMemoryWeight(gomock.Any(), chunkWeight).Return(nil)
				m.chunk.EXPECT().GetSize().Return(chunkSize)
				m.chunk.EXPECT().GetMaxPeekSize().Return(maxPeekSize)
				m.chunk.EXPECT().ReadChunk(gomock.Any(), gomock.Any()).Return("", assert.AnError)
				m.semaphore.EXPECT().ReleaseMemoryWeight(chunkWeight)
			},
			memoryBudget: 1_000,
			expectedErr:  assert.AnError,
		},
		{
			name: "large file - success & release",
			makeFile: func(tmp string) string {
				return writeTempFile(t, tmp, 0, []byte("abc\ndef\nghi\njkl\nmno\npqr\nstu\nvwx\nyz"))
			},
			mockFunc: func(m *mock) {
				m.chunk.EXPECT().GetFileThreshold().Return(sizeThreshold)
				m.chunk.EXPECT().GetSize().Return(chunkSize)
				m.chunk.EXPECT().GetMaxPeekSize().Return(maxPeekSize)
				m.semaphore.EXPECT().AcquireMemoryWeight(gomock.Any(), chunkWeight).Return(nil)
				m.chunk.EXPECT().GetSize().Return(chunkSize)
				m.chunk.EXPECT().GetMaxPeekSize().Return(maxPeekSize)
				m.chunk.EXPECT().ReadChunk(gomock.Any(), gomock.Any()).Return("abc\ndef\nghi\njkl\nmno\npqr\nstu\nvw", nil)
				m.chunk.EXPECT().ReadChunk(gomock.Any(), gomock.Any()).Return("x\nyz", nil)
				m.chunk.EXPECT().ReadChunk(gomock.Any(), gomock.Any()).Return("", io.EOF)
				m.semaphore.EXPECT().ReleaseMemoryWeight(chunkWeight)
			},
			memoryBudget: 1_000,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var logsBuffer bytes.Buffer
			log.Logger = log.Output(zerolog.ConsoleWriter{
				Out:        &logsBuffer,
				NoColor:    true,
				TimeFormat: "",
			}).Level(zerolog.DebugLevel)

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			m := newMock(ctrl)
			tc.mockFunc(m)

			cfg := newConfig()
			cfg.Rules = make(map[string]config.Rule)
			cfg.Keywords = make(map[string]struct{})
			detector := detect.NewDetector(*cfg)
			detector.MaxTargetMegaBytes = tc.maxMegabytes
			engine := &Engine{
				rules: nil,

				semaphore: m.semaphore,
				chunk:     m.chunk,
				detector:  detector,
			}

			tmp := t.TempDir()
			src := tc.makeFile(tmp)
			ctx := context.Background()
			err := engine.DetectFile(ctx, &item{source: src}, make(chan *secrets.Secret, 1))
			loggedMessage := logsBuffer.String()
			if tc.expectedErr != nil {
				require.ErrorContains(t, err, tc.expectedErr.Error())
			}
			if tc.expectedLog != "" {
				expectedLog := fmt.Sprintf(tc.expectedLog, src)
				require.Contains(t, loggedMessage, expectedLog)
			}
		})
	}
}

func TestDetectChunks(t *testing.T) {
	chunkSize := 5
	maxPeekSize := 20

	testCases := []struct {
		name        string
		makeFile    func(tmp string) string
		mockFunc    func(m *mock)
		expectedLog string
		expectedErr error
	}{
		{
			name:     "successful detection",
			makeFile: func(tmp string) string { return writeTempFile(t, tmp, 0, []byte("password=supersecret\n")) },
			mockFunc: func(m *mock) {
				m.chunk.EXPECT().GetSize().Return(chunkSize)
				m.chunk.EXPECT().GetMaxPeekSize().Return(maxPeekSize)
				m.chunk.EXPECT().ReadChunk(gomock.Any(), 0).Return("password=supersecret", nil)
				m.chunk.EXPECT().ReadChunk(gomock.Any(), 0).Return("", io.EOF)
			},
		},
		{
			name:        "non existent file",
			makeFile:    func(tmp string) string { return filepath.Join(tmp, "does-not-exist") },
			mockFunc:    func(m *mock) {},
			expectedErr: fmt.Errorf("failed to open file"),
		},
		{
			name:     "unsupported file type",
			makeFile: func(tmp string) string { return writeTempFile(t, tmp, 0, []byte{'P', 'K', 0x03, 0x04}) },
			mockFunc: func(m *mock) {
				m.chunk.EXPECT().GetSize().Return(chunkSize)
				m.chunk.EXPECT().GetMaxPeekSize().Return(maxPeekSize)
				m.chunk.EXPECT().ReadChunk(gomock.Any(), 0).Return("", fmt.Errorf("skipping file: unsupported file type"))
			},
			expectedLog: "Skipping file %s: unsupported file type",
		},
		{
			name:     "end of file error",
			makeFile: func(tmp string) string { return writeTempFile(t, tmp, 0, []byte("password=supersecret\n")) },
			mockFunc: func(m *mock) {
				m.chunk.EXPECT().GetSize().Return(chunkSize)
				m.chunk.EXPECT().GetMaxPeekSize().Return(maxPeekSize)
				m.chunk.EXPECT().ReadChunk(gomock.Any(), 0).Return("", io.EOF)
			},
		},
		{
			name:     "chunk read error",
			makeFile: func(tmp string) string { return writeTempFile(t, tmp, 0, []byte("password=supersecret\n")) },
			mockFunc: func(m *mock) {
				m.chunk.EXPECT().GetSize().Return(chunkSize)
				m.chunk.EXPECT().GetMaxPeekSize().Return(maxPeekSize)
				m.chunk.EXPECT().ReadChunk(gomock.Any(), 0).Return("", assert.AnError)
			},
			expectedErr: assert.AnError,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var logsBuffer bytes.Buffer
			log.Logger = log.Output(zerolog.ConsoleWriter{
				Out:        &logsBuffer,
				NoColor:    true,
				TimeFormat: "",
			}).Level(zerolog.DebugLevel)

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			m := newMock(ctrl)
			tc.mockFunc(m)

			cfg := newConfig()
			cfg.Rules = make(map[string]config.Rule)
			cfg.Keywords = make(map[string]struct{})
			detector := detect.NewDetector(*cfg)
			engine := &Engine{
				rules: nil,

				semaphore: m.semaphore,
				chunk:     m.chunk,
				detector:  detector,
			}
			tmp := t.TempDir()
			src := tc.makeFile(tmp)

			err := engine.detectChunks(context.Background(), &item{source: src}, make(chan *secrets.Secret, 1))
			loggedMessage := logsBuffer.String()
			if tc.expectedErr != nil {
				require.ErrorContains(t, err, tc.expectedErr.Error())
			}
			if tc.expectedLog != "" {
				expectedLog := fmt.Sprintf(tc.expectedLog, src)
				require.Contains(t, loggedMessage, expectedLog)
			}
		})
	}
}

func TestSecretsColumnIndex(t *testing.T) {

	tests := []struct {
		name                string
		lineContent         string
		startColumn         int
		endColumn           int
		expectedLineContent string
		expectedStartColumn int
		expectedEndColumn   int
	}{
		{
			name:                "secret on first line without newline",
			lineContent:         `let apikey = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"`,
			startColumn:         14,
			endColumn:           50,
			expectedLineContent: `let apikey = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"`,
			expectedStartColumn: 14,
			expectedEndColumn:   50,
		},
		{
			name:                "secret with leading newline",
			lineContent:         "\nlet apikey = \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\"",
			startColumn:         15,
			endColumn:           51,
			expectedLineContent: `let apikey = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"`,
			expectedStartColumn: 14,
			expectedEndColumn:   50,
		},
		{
			name:                "leading newline followed by tab indentation",
			lineContent:         "\n	let apikey = \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\"",
			startColumn:         2,
			endColumn:           7,
			expectedLineContent: "	let apikey = \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\"",
			expectedStartColumn: 1,
			expectedEndColumn:   6,
		},
		{
			name:                "leading newline followed by tab indentation with special character",
			lineContent:         "\n\tlet apikey€ = \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\"",
			startColumn:         2,
			endColumn:           7,
			expectedLineContent: "	let apikey€ = \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\"",
			expectedStartColumn: 1,
			expectedEndColumn:   6,
		},
		{
			name:                "newline with content larger than context limit",
			lineContent:         "\n" + strings.Repeat("A", 500) + "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + strings.Repeat("B", 500),
			startColumn:         501,
			endColumn:           536,
			expectedLineContent: strings.Repeat("A", 250) + "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + strings.Repeat("B", 250),
			expectedStartColumn: 500,
			expectedEndColumn:   535,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			mockItem := &item{content: &tt.lineContent, source: "test.txt"}

			finding := report.Finding{
				StartColumn: tt.startColumn,
				EndColumn:   tt.endColumn,
				Secret:      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
				RuleID:      "test-rule",
				Description: "Test Description",
				Line:        tt.lineContent,
				StartLine:   1,
				EndLine:     1,
			}

			fsPlugin := &plugins.FileSystemPlugin{}
			secret, err := buildSecret(context.Background(), mockItem, finding, fsPlugin.GetName())

			require.NoError(t, err)
			assert.Equal(t, tt.expectedLineContent, secret.LineContent)
			assert.Equal(t, tt.expectedStartColumn, secret.StartColumn)
			assert.Equal(t, tt.expectedEndColumn, secret.EndColumn)
		})
	}
}

func TestGetFindingId(t *testing.T) {
	// Test data setup
	mockItem1 := &item{
		id:     "test-item-1",
		source: "test-source-1.txt",
	}

	mockItem2 := &item{
		id:     "test-item-2",
		source: "test-source-2.txt",
	}

	finding1 := &report.Finding{
		RuleID: "rule-id-1",
		Secret: "my-secret-value",
	}

	finding2 := &report.Finding{
		RuleID: "rule-id-2",
		Secret: "my-secret-value",
	}

	finding3 := &report.Finding{
		RuleID: "rule-id-1",
		Secret: "different-secret-value",
	}

	tests := []struct {
		name        string
		item        plugins.ISourceItem
		finding     *report.Finding
		description string
	}{
		{
			name:        "same_inputs_consistent_id",
			item:        mockItem1,
			finding:     finding1,
			description: "Same inputs should always produce the same ID",
		},
		{
			name:        "same_inputs_consistent_id_duplicate",
			item:        mockItem1,
			finding:     finding1,
			description: "Duplicate test to verify consistency",
		},
		{
			name:        "different_item_id_different_result",
			item:        mockItem2,
			finding:     finding1,
			description: "Different item ID should produce different result",
		},
		{
			name:        "different_rule_id_different_result",
			item:        mockItem1,
			finding:     finding2,
			description: "Different rule ID should produce different result",
		},
		{
			name:        "different_secret_different_result",
			item:        mockItem1,
			finding:     finding3,
			description: "Different secret should produce different result",
		},
		{
			name: "empty_item_id",
			item: &item{
				id:     "",
				source: "test-source.txt",
			},
			finding:     finding1,
			description: "Empty item ID should still work",
		},
		{
			name: "empty_rule_id",
			item: mockItem1,
			finding: &report.Finding{
				RuleID: "",
				Secret: "my-secret-value",
			},
			description: "Empty rule ID should still work",
		},
		{
			name: "empty_secret",
			item: mockItem1,
			finding: &report.Finding{
				RuleID: "rule-id-1",
				Secret: "",
			},
			description: "Empty secret should still work",
		},
		{
			name: "unicode_characters",
			item: &item{
				id:     "test-item-unicode🔑🚀🔐",
				source: "test-source-🔑🚀🔐.txt",
			},
			finding: &report.Finding{
				RuleID: "rule-unicode",
				Secret: "secret-with-unicode🔑🚀🔐",
			},
			description: "Unicode characters should be handled properly",
		},
		{
			name: "special_characters",
			item: &item{
				id:     "test-item-special-!@#$%^&*()",
				source: "test-source-special.txt",
			},
			finding: &report.Finding{
				RuleID: "rule-special-!@#$%",
				Secret: "secret-with-special-chars-[]{}|\\:;\"'<>?,./",
			},
			description: "Special characters should be handled properly",
		},
		{
			name: "very_long_values",
			item: &item{
				id:     strings.Repeat("a", 1000),
				source: "test-source-long.txt",
			},
			finding: &report.Finding{
				RuleID: strings.Repeat("b", 1000),
				Secret: strings.Repeat("c", 10000),
			},
			description: "Very long values should be handled properly",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := getFindingId(tt.item, tt.finding)

			assert.NoError(t, err, tt.description)
			assert.NotEmpty(t, id, "ID should not be empty")
			assert.Len(t, id, 40, "ID should be 40 characters long (20 bytes as hex)")
			assert.Regexp(t, "^[a-f0-9]+$", id, "ID should be valid lowercase hex")
		})
	}

	t.Run("multiple_calls_consistency", func(t *testing.T) {
		item := mockItem1
		finding := finding1

		firstID, err := getFindingId(item, finding)
		require.NoError(t, err)

		for i := 1; i < 10; i++ {
			id, err := getFindingId(item, finding)
			require.NoError(t, err)
			assert.Equal(t, firstID, id, "Multiple calls with same inputs should produce identical results")
		}
	})

	// Test that different combinations produce different IDs
	t.Run("different_combinations_produce_different_ids", func(t *testing.T) {
		combinations := []struct {
			item    plugins.ISourceItem
			finding *report.Finding
		}{
			{mockItem1, finding1},
			{mockItem1, finding2},
			{mockItem1, finding3},
			{mockItem2, finding1},
			{mockItem2, finding2},
			{mockItem2, finding3},
		}

		seenIDs := make(map[string]bool)

		for i, combo := range combinations {
			id, err := getFindingId(combo.item, combo.finding)
			require.NoError(t, err, "Combination %d should not error", i)

			assert.False(t, seenIDs[id], "ID %s should be unique, but was seen before for combination %d", id, i)
			seenIDs[id] = true
		}

		assert.Len(t, seenIDs, len(combinations), "All combinations should produce unique IDs")
	})
}

func TestIsSecretFromConfluenceResourceIdentifier(t *testing.T) {
	tests := []struct {
		name   string
		ruleID string
		line   string
		match  string
		want   bool
	}{
		{
			name:   "matches ri:secret attribute with quoted value",
			ruleID: rules.GenericApiKeyID,
			line:   `<ri:attachment ri:secret="12345" />`,
			match:  `secret="12345"`,
			want:   true,
		},
		{
			name:   "matches with extra whitespace and self-closing tag",
			ruleID: rules.GenericApiKeyID,
			line:   `<ri:attachment     ri:secret="12345"/>`,
			match:  `secret="12345"`,
			want:   true,
		},
		{
			name:   "no match when value format differs (expects exact literal)",
			ruleID: rules.GenericApiKeyID,
			line:   `<ri:attachment ri:secret="12345" />`,
			match:  `secret=12345`,
			want:   false,
		},
		{
			name:   "no match when value appears in a different attribute",
			ruleID: rules.GenericApiKeyID,
			line:   `<ri:attachment ri:filename="secret=12345" />`,
			match:  `secret=12345`,
			want:   false,
		},
		{
			name:   "no match when ri: prefixes the element name (not an attribute)",
			ruleID: rules.GenericApiKeyID,
			line:   `<ri:secret value="x">`,
			match:  `secret`,
			want:   false,
		},
		{
			name:   "no match when text is outside any tag",
			ruleID: rules.GenericApiKeyID,
			line:   `ri:secret=12345`,
			match:  `secret=12345`,
			want:   false,
		},
		{
			name:   "no match for xri: prefixed attribute",
			ruleID: rules.GenericApiKeyID,
			line:   `<ri:attachment xri:secret="12345" />`,
			match:  `secret="12345"`,
			want:   false,
		},
		{
			name:   "no match when rule ID is not generic-api-key does not apply",
			ruleID: "some-other-rule",
			line:   `<ri:attachment ri:secret="12345" />`,
			match:  `secret="12345"`,
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSecretFromConfluenceResourceIdentifier(tt.ruleID, tt.line, tt.match)
			assert.Equal(t, tt.want, got, "ruleID=%q, line=%q, match=%q", tt.ruleID, tt.line, tt.match)
		})
	}
}

// if any of these tests fails, we should review isSecretFromConfluenceResourceIdentifier and/or generic-api-key rule
func TestDetectWithConfluenceMetadata(t *testing.T) {
	secretsCases := []struct {
		Content    string
		Name       string
		ShouldFind bool
	}{
		{
			Content:    "<ri:user ri:userkey=\"8a7f808362ce64321162ceb20e64321a\" >",
			Name:       "should not detect from confluence userkey metadata",
			ShouldFind: false,
		},
	}

	detector, err := Init(&EngineConfig{})
	if err != nil {
		t.Fatal(err)
	}

	for _, secret := range secretsCases {
		t.Run(secret.Name, func(t *testing.T) {
			secretsChan := make(chan *secrets.Secret, 1)
			c := plugins.ConfluencePlugin{}
			err = detector.DetectFragment(item{content: &secret.Content}, secretsChan, c.GetName())
			if err != nil {
				return
			}
			close(secretsChan)

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

func (i item) GetGitInfo() *plugins.GitInfo {
	return nil
}

// writeTempFile writes either the provided content or a buffer of 'size' bytes
func writeTempFile(t *testing.T, dir string, size int, content []byte) string {
	t.Helper()

	f, err := os.CreateTemp(dir, "testfile-*.tmp")
	require.NoError(t, err, "create temp file")
	defer f.Close() //nolint:errcheck

	var data []byte
	if content != nil {
		data = content
	} else {
		data = make([]byte, size)
		for i := range data {
			data[i] = 'a'
		}
	}

	_, err = f.Write(data)
	require.NoError(t, err, "write temp file")

	return f.Name()
}

func TestProcessItems(t *testing.T) {
	totalItemsToProcess := 5
	engineTest, err := initEngine(&EngineConfig{})
	assert.NoError(t, err)
	defer engineTest.Shutdown()

	pluginName := "mockPlugin"
	pluginChannels := engineTest.GetPluginChannels()

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		engineTest.processItems(pluginName)
	}()

	ctrl := gomock.NewController(t)
	for i := range totalItemsToProcess {
		mockData := strconv.Itoa(i)
		mockItem := NewMockISourceItem(ctrl)
		mockItem.EXPECT().GetContent().Return(&mockData).AnyTimes()
		mockItem.EXPECT().GetID().Return(mockData).AnyTimes()
		mockItem.EXPECT().GetSource().Return(pluginName).AnyTimes()
		pluginChannels.GetItemsCh() <- mockItem
	}
	close(pluginChannels.GetItemsCh())
	wg.Wait()
	assert.Equal(t, totalItemsToProcess, engineTest.GetReport().GetTotalItemsScanned())
}

func TestProcessSecrets(t *testing.T) {
	t.Run("Validate flag is enabled", func(t *testing.T) {
		instance, err := initEngine(&EngineConfig{
			ScanConfig: resources.ScanConfig{
				WithValidation: true,
			},
		})
		assert.NoError(t, err)
		secretsChan := instance.secretsChan
		secretsChan <- &secrets.Secret{ID: "mockId", StartLine: 1}
		secretsChan <- &secrets.Secret{ID: "mockId2"}
		secretsChan <- &secrets.Secret{ID: "mockId", StartLine: 2}
		close(secretsChan)

		instance.processSecrets()

		expectedSecrets := []*secrets.Secret{
			{ID: "mockId", StartLine: 1},
			{ID: "mockId", StartLine: 2},
			{ID: "mockId2"},
		}
		secretsExtrasChan := instance.GetSecretsExtrasCh()
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

		cvssScoreWithoutValidationChan := instance.GetCvssScoreWithoutValidationCh()
		validationChan := instance.GetValidationCh()
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
		assert.Equal(t, 3, instance.GetReport().GetTotalSecretsFound())
		assert.Equal(t, 2, len(instance.GetReport().GetResults()["mockId"]))
		assert.Equal(t, 1, len(instance.GetReport().GetResults()["mockId2"]))
		assert.Equal(t, &secrets.Secret{ID: "mockId", StartLine: 1}, instance.GetReport().GetResults()["mockId"][0])
		assert.Equal(t, &secrets.Secret{ID: "mockId", StartLine: 2}, instance.GetReport().GetResults()["mockId"][1])
		assert.Equal(t, &secrets.Secret{ID: "mockId2"}, instance.GetReport().GetResults()["mockId2"][0])
	})
	t.Run("Validate flag is disabled", func(t *testing.T) {
		instance, err := initEngine(&EngineConfig{
			ScanConfig: resources.ScanConfig{
				WithValidation: false,
			},
		})
		assert.NoError(t, err)
		secretsChan := instance.secretsChan
		secretsChan <- &secrets.Secret{ID: "mockId", StartLine: 1}
		secretsChan <- &secrets.Secret{ID: "mockId2"}
		secretsChan <- &secrets.Secret{ID: "mockId", StartLine: 2}
		close(secretsChan)

		instance.processSecrets()

		expectedSecrets := []*secrets.Secret{
			{ID: "mockId", StartLine: 1},
			{ID: "mockId", StartLine: 2},
			{ID: "mockId2"},
		}
		secretsExtrasChan := instance.GetSecretsExtrasCh()
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

		validationChan := instance.GetValidationCh()
		cvssScoreWithoutValidationChan := instance.GetCvssScoreWithoutValidationCh()
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

		assert.Equal(t, 3, instance.GetReport().GetTotalSecretsFound())
		assert.Equal(t, 2, len(instance.GetReport().GetResults()["mockId"]))
		assert.Equal(t, 1, len(instance.GetReport().GetResults()["mockId2"]))
		assert.Equal(t, &secrets.Secret{ID: "mockId", StartLine: 1}, instance.GetReport().GetResults()["mockId"][0])
		assert.Equal(t, &secrets.Secret{ID: "mockId", StartLine: 2}, instance.GetReport().GetResults()["mockId"][1])
		assert.Equal(t, &secrets.Secret{ID: "mockId2"}, instance.GetReport().GetResults()["mockId2"][0])
	})
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
			instance, err := initEngine(&EngineConfig{})
			assert.NoError(t, err)
			secretsExtrasChan := instance.GetSecretsExtrasCh()
			for _, secret := range tt.inputSecrets {
				secretsExtrasChan <- secret
			}
			close(secretsExtrasChan)

			instance.processSecretsExtras()

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
			instance, err := initEngine(&EngineConfig{ScanConfig: resources.ScanConfig{WithValidation: true}})
			assert.NoError(t, err)
			validationChan := instance.GetValidationCh()
			for _, secret := range tt.inputSecrets {
				validationChan <- secret
			}
			close(validationChan)

			instance.processScore()

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
			instance, err := initEngine(&EngineConfig{})
			assert.NoError(t, err)
			defer instance.Shutdown()

			cvssScoreWithoutValidationChan := instance.GetCvssScoreWithoutValidationCh()
			for _, secret := range tt.inputSecrets {
				cvssScoreWithoutValidationChan <- secret
			}
			close(cvssScoreWithoutValidationChan)

			instance.processScore()

			for i, expected := range tt.expectedSecrets {
				assert.Equal(t, expected, tt.inputSecrets[i])
			}
		})
	}
}
