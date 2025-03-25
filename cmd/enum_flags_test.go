package cmd

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIgnoreOnExitSet(t *testing.T) {
	tests := []struct {
		input    string
		expected ignoreOnExit
		err      bool
	}{
		{"none", ignoreOnExitNone, false},
		{"all", ignoreOnExitAll, false},
		{"results", ignoreOnExitResults, false},
		{"errors", ignoreOnExitErrors, false},
		{"invalid", "", true},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("Set(%s)", tt.input), func(t *testing.T) {
			var i ignoreOnExit
			err := i.Set(tt.input)
			if tt.err {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, i)
			}
		})
	}
}
