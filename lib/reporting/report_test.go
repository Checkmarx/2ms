package reporting

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/checkmarx/2ms/lib/config"
	"github.com/checkmarx/2ms/lib/secrets"
)

func TestAddSecretToFile(t *testing.T) {
	secretValue := string(`
-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCKLwIHewTIhcpH3WLnxZ61xBAk2lnkdahFxjHYi+khrENzbGr8
EeJDZ1FMUDDYGeLtjlROLHT41ovicFbsmgIU0QQVFewIAwvKIw5hBtq0TtO9CsXe
BaNmzw8ZduXJ/clOpdOF7/1ro485a+v956ZAhB2ohbk6qRqGyg3kaxclOQIDAQAB
AoGAV7z5QN6vbtLkWTUMc7VazHas+Xla0mCSc5sgUyqi4CqMuWEBnQON8tZLHHVe
ThhBqixRA0HfE5DGSQSjbJ9s6fD+Sjt0Qj2yer70FuEiR0uGM4tOAE7WbX+Ny7PT
gmDiWOITe7v0yzIgZzbLgPhg5SlCmiy8Nv2Zf/v54yLVPLECQQDbwpsuu6beMDip
kRB/msCAEEAstdfSPY8L9QySYxskkJvtWpWBu5trnRatiGoLYWvnsBzcL4xWGrs8
Tpr4hTirAkEAoPiRDHrVbkKAgrmLW/TrSDiOG8uXSTuvz4iFgzCG6Cd8bp7mDKhJ
l98Upelf0Is5sEnLDqnFl62LZAyckeThqwJAOjZChQ6QFSsQ11nl1OdZNpMXbMB+
euJzkedHfT9jYTwtEaJ9F/BqKwdhinYoIPudabHs8yZlNim+jysDQfGIIQJAGqlx
JPcHeO7M6FohKgcEHX84koQDN98J/L7pFlSoU7WOl6f8BKavIdeSTPS9qQYWdQuT
9YbLMpdNGjI4kLWvZwJAJt8Qnbc2ZfS0ianwphoOdB0EwOMKNygjnYx7VoqR9/h1
4Xgur9w/aLZrLM3DSatR+kL+cVTyDTtgCt9Dc8k48Q==
-----END RSA PRIVATE KEY-----`)

	results := map[string][]*secrets.Secret{}
	report := Report{len(results), 1, results}
	secret := &secrets.Secret{Source: "bla", StartLine: 1, StartColumn: 0, EndLine: 1, EndColumn: 0, Value: secretValue}
	source := "directory\\rawStringAsFile.txt"

	report.Results[source] = append(report.Results[source], secret)

	key, fileExist := report.Results[source]
	if !fileExist {
		t.Errorf("key %s not added", source)
	}

	if !reflect.DeepEqual(report.Results, results) {
		t.Errorf("got %+v want %+v", key, results)
	}
}

func TestWriteReportInNonExistingDir(t *testing.T) {
	report := Init()

	tempDir := os.TempDir()
	path := filepath.Join(tempDir, "test_temp_dir", "sub_dir", "report.yaml")
	err := report.WriteFile([]string{path}, &config.Config{Name: "report", Version: "5"})
	if err != nil {
		t.Error(err)
	}

	os.RemoveAll(filepath.Join(tempDir, "test_temp_dir"))
}
