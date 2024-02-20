package secrets

import (
	"testing"
)

func TestValidationResultCompareTo(t *testing.T) {
	testCases := []struct {
		first   ValidationResult
		second  ValidationResult
		want    compared
		message string
	}{
		{
			first:   ValidResult,
			second:  ValidResult,
			want:    equal,
			message: "Valid should be equal to Valid",
		},
		{
			first:   RevokedResult,
			second:  ValidResult,
			want:    second,
			message: "Valid should be greater than Revoked",
		},
		{
			first:   ValidResult,
			second:  UnknownResult,
			want:    first,
			message: "Valid should be greater than Unknown",
		},
		{
			first:   UnknownResult,
			second:  RevokedResult,
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
