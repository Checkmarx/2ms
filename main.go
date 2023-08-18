package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/checkmarx/2ms/cmd"
	"github.com/checkmarx/2ms/lib"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Logger = lib.CreateLogger(zerolog.InfoLevel)

	// this block sets up a go routine to listen for an interrupt signal
	// which will immediately exit gitleaks
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt)
	go listenForInterrupt(stopChan)

	if err := cmd.Execute(); err != nil {
		if cmd.ShowError("errors") {
			fmt.Println(err)
			os.Exit(1)
		}
	}
}

func listenForInterrupt(stopScan chan os.Signal) {
	<-stopScan
	log.Fatal().Msg("Interrupt signal received. Exiting...")
}
