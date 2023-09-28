package cmd

import (
	"os"
)

const (
	errorCode   = 1
	resultsCode = 2
)

func isNeedReturnErrorCodeFor(kind ignoreOnExit) bool {
	if ignoreOnExitVar == ignoreOnExitNone {
		return true
	}

	if ignoreOnExitVar == ignoreOnExitAll {
		return false
	}

	if ignoreOnExitVar != ignoreOnExit(kind) {
		return true
	}

	return false
}

func exitCodeIfError(err error) int {
	if err != nil && isNeedReturnErrorCodeFor("errors") {
		return errorCode
	}

	return 0
}

func exitCodeIfResults(resultsCount int) int {
	if resultsCount > 0 && isNeedReturnErrorCodeFor("results") {
		return resultsCode
	}

	return 0
}

func Exit(resultsCount int, err error) {
	os.Exit(exitCodeIfError(err) + exitCodeIfResults(resultsCount))
}

func listenForErrors(errors chan error) {
	go func() {
		err := <-errors
		Exit(0, err)
	}()
}
