package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// test for GetDefaultRules is in internal/rule/rule_test.go
func TestLoadAllRules(t *testing.T) {
	rules := GetDefaultRules(false)
	assert.Equal(t, len(rules), 212)
}
