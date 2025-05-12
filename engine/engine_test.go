package engine

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/checkmarx/2ms/engine/rules"
	"github.com/checkmarx/2ms/lib/secrets"
	"github.com/checkmarx/2ms/plugins"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/semaphore"
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
	smallSize := 10                                   // 10 bytes
	chunkWeight := int64(4*ChunkSize + 2*MaxPeekSize) // 450KiB

	testCases := []struct {
		name         string
		makeFile     func(tmp string) string
		maxMegabytes int
		memoryBudget int64
		wantRelease  func(sem *semaphore.Weighted) (weight int64)
		expectedErr  error
	}{
		{
			name:         "non existent file",
			makeFile:     func(tmp string) string { return filepath.Join(tmp, "does-not-exist") },
			memoryBudget: 1_000,
			expectedErr:  fmt.Errorf("failed to stat"),
		},
		{
			name:         "exceed max megabytes",
			makeFile:     func(tmp string) string { return writeTempFile(t, tmp, 2000000, nil) /* 2MB */ },
			maxMegabytes: 1,
			memoryBudget: 1_000,
		},
		{
			name:         "small file - memory too low",
			makeFile:     func(tmp string) string { return writeTempFile(t, tmp, smallSize, nil) },
			memoryBudget: int64(smallSize*2) - 1, // 19 bytes < 2*10 bytes
			expectedErr:  fmt.Errorf("buffer size"),
		},
		{
			name:         "small file - acquire error",
			makeFile:     func(tmp string) string { return writeTempFile(t, tmp, smallSize, nil) },
			memoryBudget: int64(smallSize * 2), // 20 bytes >= 2*10 bytes
			expectedErr:  fmt.Errorf("failed to acquire semaphore"),
		},
		{
			name:         "small file - success & release",
			makeFile:     func(tmp string) string { return writeTempFile(t, tmp, smallSize, nil) },
			memoryBudget: 1_000,
			wantRelease: func(sem *semaphore.Weighted) (weight int64) {
				return int64(smallSize * 2)
			},
		},
		{
			name:         "large file - memory too low",
			makeFile:     func(tmp string) string { return writeTempFile(t, tmp, SmallFileThreshold+1, nil) },
			memoryBudget: chunkWeight - 1, // 450KB - 1 byte < 450KB
			expectedErr:  fmt.Errorf("buffer size"),
		},
		{
			name:         "large file - acquire error",
			makeFile:     func(tmp string) string { return writeTempFile(t, tmp, SmallFileThreshold+1, nil) },
			memoryBudget: chunkWeight, // 450KB >= 450KB
			expectedErr:  fmt.Errorf("failed to acquire semaphore"),
		},
		{
			name:         "large file - success & release",
			makeFile:     func(tmp string) string { return writeTempFile(t, tmp, SmallFileThreshold+1, nil) },
			memoryBudget: chunkWeight + 1,
			wantRelease: func(_ *semaphore.Weighted) (weight int64) {
				return chunkWeight
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			eng, err := Init(EngineConfig{MaxTargetMegabytes: tc.maxMegabytes})
			if err != nil {
				t.Fatal(err)
			}
			tmp := t.TempDir()
			src := tc.makeFile(tmp)

			sem := semaphore.NewWeighted(1 * 1024 * 1024) // 1MiB

			ctx := context.Background()
			// Cancel context immediately to simulate a acquire error
			if tc.expectedErr != nil && tc.expectedErr.Error() == "failed to acquire semaphore" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			err = eng.DetectFile(ctx, &item{source: src}, make(chan *secrets.Secret, 1), tc.memoryBudget, sem)
			if tc.expectedErr != nil {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.expectedErr.Error())
			} else if tc.wantRelease != nil {
				require.NoError(t, err)
				// Verify that it Release() exactly once for the right weight
				weight := tc.wantRelease(sem)
				ok := sem.TryAcquire(weight)
				require.True(t, ok, "expected semaphore to have released %d", weight)
				// Clean up
				sem.Release(weight)
			}
		})
	}
}

func TestDetectChunks(t *testing.T) {
	testCases := []struct {
		name        string
		makeFile    func(tmp string) string
		expectedLog string
		expectedErr error
	}{
		{
			name:     "successful detection",
			makeFile: func(tmp string) string { return writeTempFile(t, tmp, 0, []byte("password=supersecret\n")) },
		},
		{
			name:        "unsupported file type",
			makeFile:    func(tmp string) string { return writeTempFile(t, tmp, 0, []byte{'P', 'K', 0x03, 0x04}) },
			expectedLog: "Skipping file %s: unsupported file type",
		},
		{
			name:        "non existent file",
			makeFile:    func(tmp string) string { return filepath.Join(tmp, "does-not-exist") },
			expectedErr: fmt.Errorf("failed to open file"),
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

			eng, err := Init(EngineConfig{})
			require.NoError(t, err)
			tmp := t.TempDir()
			src := tc.makeFile(tmp)
			it := &item{
				source: src,
			}

			err = eng.DetectChunks(it, make(chan *secrets.Secret, 1))
			loggedMessage := logsBuffer.String()
			if tc.expectedErr != nil {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.expectedErr.Error())
			} else {
				if tc.expectedLog != "" {
					expectedLog := fmt.Sprintf(tc.expectedLog, src)
					require.Contains(t, loggedMessage, expectedLog)
				}
				require.NoError(t, err)
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
	defer f.Close()

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
