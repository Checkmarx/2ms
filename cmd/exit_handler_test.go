package cmd

import (
	"fmt"
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
