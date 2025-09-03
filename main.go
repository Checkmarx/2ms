package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/checkmarx/2ms/v4/cmd"
	"github.com/checkmarx/2ms/v4/lib/utils"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Logger = utils.CreateLogger(zerolog.InfoLevel)

	// this block sets up a go routine to listen for an interrupt signal
	// which will immediately exit gitleaks
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt)
	go listenForInterrupt(stopChan)

	exitCode, err := cmd.Execute()
	if err != nil {
		log.Error().Err(err).Msg("Error in 2ms")
	}

	fmt.Println("exitCode of cmd.Execute()", exitCode)

	cmd.Exit(exitCode, err)
}

func listenForInterrupt(stopScan chan os.Signal) {
	<-stopScan
	log.Error().Msg("Interrupt signal received. Exiting...")
	os.Exit(1)
}
