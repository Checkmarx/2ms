package runner

import (
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestFileSystemRunner(t *testing.T) {
	tests := []struct {
		name               string
		path               string
		projectName        string
		ignored            []string
		expectedOutputFile string
		expectedError      error
	}{
		{
			name:               "Valid path with files",
			path:               "testData/secrets",
			projectName:        "TestProject",
			ignored:            []string{},
			expectedOutputFile: "testData/expectedReport.json",
			expectedError:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := NewFileSystemRunner()

			output, err := runner.Run(tt.path, tt.projectName, tt.ignored)
			assert.Equal(t, tt.expectedError, err)

			expectedBytes, readErr := os.ReadFile(tt.expectedOutputFile)
			assert.NoError(t, readErr, "failed to read expected output file")

			expectedOutput := string(expectedBytes)
			assert.Equal(t, expectedOutput, output, "output mismatch")
		})
	}
}
