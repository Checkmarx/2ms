package engine

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/mock/gomock"

	"github.com/checkmarx/2ms/v3/engine/chunk"
	"github.com/checkmarx/2ms/v3/engine/rules"
	"github.com/checkmarx/2ms/v3/engine/semaphore"
	"github.com/checkmarx/2ms/v3/lib/secrets"
	"github.com/checkmarx/2ms/v3/plugins"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/report"
)

var fsPlugin = &plugins.FileSystemPlugin{}

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
		err = detector.DetectFragment(i, secretsChan, fsPlugin.GetName())
		if err != nil {
			return
		}
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

			cfg.Rules = make(map[string]config.Rule)
			cfg.Keywords = []string{}
			detector := detect.NewDetector(cfg)
			detector.MaxTargetMegaBytes = tc.maxMegabytes
			engine := &Engine{
				rules: nil,

				semaphore: m.semaphore,
				chunk:     m.chunk,
				detector:  *detector,
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

			cfg.Rules = make(map[string]config.Rule)
			cfg.Keywords = []string{}
			detector := detect.NewDetector(cfg)
			engine := &Engine{
				rules: nil,

				semaphore: m.semaphore,
				chunk:     m.chunk,
				detector:  *detector,
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

			secret, err := buildSecret(context.Background(), mockItem, finding, fsPlugin.GetName())

			require.NoError(t, err)
			assert.Equal(t, tt.expectedLineContent, secret.LineContent)
			assert.Equal(t, tt.expectedStartColumn, secret.StartColumn)
			assert.Equal(t, tt.expectedEndColumn, secret.EndColumn)
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
