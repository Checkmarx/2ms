package reporting

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateMessageText(t *testing.T) {
	messagePrefix := "Test Rule has detected secret for file %s."
	
	tests := []struct {
		Name            string
		RuleName        string
		FilePath        string
		ExpectedMessage string
	}{
		{
			Name:            "Filesystem file name",
			RuleName:        ruleName,
			FilePath:        "folder/filename.txt",
			ExpectedMessage: sprintf(messagePrefix, "folder/filename.txt"),
		},
		{
			Name:            "Simple git filename",
			RuleName:        ruleName,
			FilePath:        "git show 1a9f3c87b4d029f54e8c72d8b11a78f6a3c29d2e:folder/filename.txt",
			ExpectedMessage: sprintf(messagePrefix, "folder/filename.txt"),
		},
		{
			Name:            "Broken git file name with no commit hash",
			RuleName:        ruleName,
			FilePath:        "git show folder/filename.txt",
			ExpectedMessage: sprintf(messagePrefix, "folder/filename.txt"),
		},
		{
			Name:            "Git file name with one colon character",
			RuleName:        ruleName,
			FilePath:        "git show d8e914f06d8d4494bd4f9ab2a2c9c88f78ef25ad:folder/filename:secondpart.txt",
			ExpectedMessage: sprintf(messagePrefix, "folder/filename:secondpart.txt"),
		},
		{
			Name:            "Git file name with multiple colon character",
			RuleName:        ruleName,
			FilePath:        "git show a73b5cf94f0b29e1cc6e71a092f6b8ebc1d0e002:folder:secondfolderpart/filename:secondpart.txt",
			ExpectedMessage: sprintf(messagePrefix, "folder:secondfolderpart/filename:secondpart.txt"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			message := createMessageText(tt.RuleName, tt.FilePath)
			fmt.Printf("%v", message)
			assert.Equal(t, tt.ExpectedMessage, message)
		})
	}
}
