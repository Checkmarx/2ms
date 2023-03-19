package reporting

import (
	"reflect"
	"testing"
)

func TestAddSecretToFile(t *testing.T) {
	secretValue := "-----BEGIN RSA PRIVATE KEY-----\nMIICWwIBAAKBgQCKLwIHewTIhcpH3WLnxZ61xBAk2lnkdahFxjHYi+khrENzbGr8\nEeJDZ1FMUDDYGeLtjlROLHT41ovicFbsmgIU0QQVFewIAwvKIw5hBtq0TtO9CsXe\nBaNmzw8ZduXJ/clOpdOF7/1ro485a+v956ZAhB2ohbk6qRqGyg3kaxclOQIDAQAB\nAoGAV7z5QN6vbtLkWTUMc7VazHas+Xla0mCSc5sgUyqi4CqMuWEBnQON8tZLHHVe\nThhBqixRA0HfE5DGSQSjbJ9s6fD+Sjt0Qj2yer70FuEiR0uGM4tOAE7WbX+Ny7PT\ngmDiWOITe7v0yzIgZzbLgPhg5SlCmiy8Nv2Zf/v54yLVPLECQQDbwpsuu6beMDip\nkRB/msCAEEAstdfSPY8L9QySYxskkJvtWpWBu5trnRatiGoLYWvnsBzcL4xWGrs8\nTpr4hTirAkEAoPiRDHrVbkKAgrmLW/TrSDiOG8uXSTuvz4iFgzCG6Cd8bp7mDKhJ\nl98Upelf0Is5sEnLDqnFl62LZAyckeThqwJAOjZChQ6QFSsQ11nl1OdZNpMXbMB+\neuJzkedHfT9jYTwtEaJ9F/BqKwdhinYoIPudabHs8yZlNim+jysDQfGIIQJAGqlx\nJPcHeO7M6FohKgcEHX84koQDN98J/L7pFlSoU7WOl6f8BKavIdeSTPS9qQYWdQuT\n9YbLMpdNGjI4kLWvZwJAJt8Qnbc2ZfS0ianwphoOdB0EwOMKNygjnYx7VoqR9/h1\n4Xgur9w/aLZrLM3DSatR+kL+cVTyDTtgCt9Dc8k48Q==\n-----END RSA PRIVATE KEY-----"
	results := map[string][]Secret{}
	report := Report{results, 1}
	secret := Secret{Description: "bla", StartLine: 0, StartColumn: 0, EndLine: 0, EndColumn: 0, Value: secretValue}
	source := "directory\\rawStringAsFile.txt"

	report.Results[source] = append(report.Results[source], secret)

	key, fileExist := report.Results[source]
	if !fileExist {
		t.Errorf("key %s not added", source)
	}

	if !reflect.DeepEqual(report.Results, results) {
		t.Errorf("got %q want %q", key, results)
	}
}
