package secrets

import (
	"testing"
)

func TestValidationResultCompareTo(t *testing.T) {
	testCases := []struct {
		first   validationResult
		second  validationResult
		want    compared
		message string
	}{
		{
			first:   Valid,
			second:  Valid,
			want:    equal,
			message: "Valid should be equal to Valid",
		},
		{
			first:   Revoked,
			second:  Valid,
			want:    second,
			message: "Valid should be greater than Revoked",
		},
		{
			first:   Valid,
			second:  Unknown,
			want:    first,
			message: "Valid should be greater than Unknown",
		},
		{
			first:   Unknown,
			second:  Revoked,
			want:    second,
			message: "Revoked should be greater than Unknown",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.message, func(t *testing.T) {
			got := tc.first.CompareTo(tc.second)
			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		},
		)
	}
}
