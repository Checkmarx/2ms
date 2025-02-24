package scanner

import (
	"encoding/json"
	"fmt"
	"github.com/checkmarx/2ms/cmd"
	"github.com/checkmarx/2ms/lib/secrets"
	"github.com/checkmarx/2ms/plugins"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

const (
	githubPatPath      = "testData/secrets/github-pat.txt"
	jwtPath            = "testData/secrets/jwt.txt"
	expectedReportPath = "testData/expectedSecretsReport.json"
)

func TestScan(t *testing.T) {
	cmd.SecretsChan = make(chan *secrets.Secret)
	cmd.SecretsExtrasChan = make(chan *secrets.Secret)
	cmd.ValidationChan = make(chan *secrets.Secret)
	cmd.CvssScoreWithoutValidationChan = make(chan *secrets.Secret)
	cmd.Channels.Items = make(chan plugins.ISourceItem)

	githubPatBytes, err := os.ReadFile(githubPatPath)
	assert.NoError(t, err, "failed to read github-pat file")
	githubPatContent := string(githubPatBytes)

	jwtBytes, err := os.ReadFile(jwtPath)
	assert.NoError(t, err, "failed to read jwt file")
	jwtContent := string(jwtBytes)

	emptyContent := ""
	emptyMockPath := "mockPath"

	scanItems := []ScanItem{
		{
			Content: &githubPatContent,
			ID:      fmt.Sprintf("mock-%s", githubPatPath),
			Source:  githubPatPath,
		},
		{
			Content: &emptyContent,
			ID:      fmt.Sprintf("mock-%s", emptyMockPath),
			Source:  emptyMockPath,
		},
		{
			Content: &jwtContent,
			ID:      fmt.Sprintf("mock-%s", jwtPath),
			Source:  jwtPath,
		},
	}

	testScanner := NewScanner()
	actualReport, err := testScanner.Scan(scanItems)
	assert.NoError(t, err, "scanner encountered an error")

	expectedReportBytes, err := os.ReadFile(expectedReportPath)
	assert.NoError(t, err, "failed to read expected report file")

	var expectedReport, actualReportMap map[string]interface{}
	err = json.Unmarshal(expectedReportBytes, &expectedReport)
	assert.NoError(t, err, "failed to unmarshal expected report JSON")

	err = json.Unmarshal([]byte(actualReport), &actualReportMap)
	assert.NoError(t, err, "failed to unmarshal actual report JSON")

	if !cmp.Equal(expectedReport, actualReportMap) {
		t.Errorf("Scan report does not match the expected report:\n%s", cmp.Diff(expectedReport, actualReportMap))
	}
}

func TestScanWithErrors(t *testing.T) {
	cmd.SecretsChan = make(chan *secrets.Secret)
	cmd.SecretsExtrasChan = make(chan *secrets.Secret)
	cmd.ValidationChan = make(chan *secrets.Secret)
	cmd.CvssScoreWithoutValidationChan = make(chan *secrets.Secret)
	cmd.Channels.Items = make(chan plugins.ISourceItem)

	emptyContent := ""
	scanItems := []ScanItem{
		{
			Content: &emptyContent,
			ID:      "",
			Source:  "",
		},
		{
			Content: &emptyContent,
			ID:      "",
			Source:  "",
		},
	}

	testScanner := NewScanner()
	cmd.Channels.Errors = make(chan error, 2)

	go func() {
		cmd.Channels.Errors <- fmt.Errorf("mock processing error 1")
		cmd.Channels.Errors <- fmt.Errorf("mock processing error 2")
	}()
	report, err := testScanner.Scan(scanItems)

	assert.Equal(t, "", report)
	assert.NotNil(t, err)
	assert.Equal(t, "error(s) processing scan items:\nmock processing error 1\nmock processing error 2", err.Error())
}
