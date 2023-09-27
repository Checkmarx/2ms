package cmd

import (
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
)

func IsNeedReturnErrorCodeFor(kind ignoreOnExit) bool {
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

func listenForErrors(errors chan error) {
	go func() {
		for err := range errors {
			// TODO: consider it should be also a generic function to be used on errorChan, on error, and on results
			if IsNeedReturnErrorCodeFor("errors") {
				fmt.Println(err.Error())
				os.Exit(1)
			}

			log.Error().Err(err).Msg("error while scanning")
			os.Exit(0)
		}
	}()
}
