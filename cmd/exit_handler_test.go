package cmd

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestExitHandler_IsNeedReturnErrorCode(t *testing.T) {

	var onErrorsTests = []struct {
		userInput      ignoreOnExit
		expectedResult bool
	}{
		{
			userInput:      ignoreOnExitNone,
			expectedResult: true,
		},
		{
			userInput:      ignoreOnExitAll,
			expectedResult: false,
		},
		{
			userInput:      ignoreOnExitResults,
			expectedResult: true,
		},
		{
			userInput:      ignoreOnExitErrors,
			expectedResult: false,
		},
	}

	for idx, testCase := range onErrorsTests {
		t.Run(fmt.Sprintf("Print test case %d", idx), func(t *testing.T) {
			ignoreOnExitVar = testCase.userInput
			result := isNeedReturnErrorCodeFor("errors")
			if result != testCase.expectedResult {
				t.Errorf("Expected %v, got %v", testCase.expectedResult, result)
			}
		})
	}

	var onResultsTests = []struct {
		userInput      ignoreOnExit
		expectedResult bool
	}{
		{
			userInput:      ignoreOnExitNone,
			expectedResult: true,
		},
		{
			userInput:      ignoreOnExitAll,
			expectedResult: false,
		},
		{
			userInput:      ignoreOnExitResults,
			expectedResult: false,
		},
		{
			userInput:      ignoreOnExitErrors,
			expectedResult: true,
		},
	}

	for idx, testCase := range onResultsTests {
		t.Run(fmt.Sprintf("Print test case %d", idx), func(t *testing.T) {
			ignoreOnExitVar = testCase.userInput
			result := isNeedReturnErrorCodeFor("results")
			if result != testCase.expectedResult {
				t.Errorf("Expected %v, got %v", testCase.expectedResult, result)
			}
		})
	}
}

func TestExitCodeIfError(t *testing.T) {
	testCases := []struct {
		name         string
		err          error
		ignoreOnExit ignoreOnExit
		expectedCode int
	}{
		{
			name:         "No error, ignoreOnExitNone",
			err:          nil,
			ignoreOnExit: ignoreOnExitNone,
			expectedCode: 0,
		},
		{
			name:         "Error present, ignoreOnExitNone",
			err:          fmt.Errorf("sample error"),
			ignoreOnExit: ignoreOnExitNone,
			expectedCode: errorCode,
		},
		{
			name:         "Error present, ignoreOnExitAll",
			err:          fmt.Errorf("sample error"),
			ignoreOnExit: ignoreOnExitAll,
			expectedCode: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ignoreOnExitVar = tc.ignoreOnExit
			code := exitCodeIfError(tc.err)
			assert.Equal(t, tc.expectedCode, code)
		})
	}
}

func TestExitCodeIfResults(t *testing.T) {
	testCases := []struct {
		name         string
		resultsCount int
		ignoreOnExit ignoreOnExit
		expectedCode int
	}{
		{
			name:         "No results, ignoreOnExitNone",
			resultsCount: 0,
			ignoreOnExit: ignoreOnExitNone,
			expectedCode: 0,
		},
		{
			name:         "Results present, ignoreOnExitNone",
			resultsCount: 5,
			ignoreOnExit: ignoreOnExitNone,
			expectedCode: resultsCode,
		},
		{
			name:         "Results present, ignoreOnExitAll",
			resultsCount: 5,
			ignoreOnExit: ignoreOnExitAll,
			expectedCode: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ignoreOnExitVar = tc.ignoreOnExit
			code := exitCodeIfResults(tc.resultsCount)
			assert.Equal(t, tc.expectedCode, code)
		})
	}
}
