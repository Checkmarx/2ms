package cmd

import "testing"

func TestIsValidFilter_validFilters(t *testing.T) {
	filters := []string{"id", "key"}

	isValidFilter := isValidFilter(filters)

	if !isValidFilter {
		t.Errorf("invalid filter")
	}
}

func TestIsValidFilter_InvalidFilters(t *testing.T) {
	filters := []string{"id", "someFilter"}

	isValidFilter := isValidFilter(filters)

	if isValidFilter {
		t.Errorf("invalid filter")
	}
}

func TestIsValidFilter_InvalidFilter(t *testing.T) {
	filters := []string{"someFilter"}

	isValidFilter := isValidFilter(filters)

	if isValidFilter {
		t.Errorf("invalid filter")
	}
}
