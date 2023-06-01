package main

import (
	"os"
	"os/signal"

	"github.com/checkmarx/2ms/cmd"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	// send all logs to stdout
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05"})

	// this block sets up a go routine to listen for an interrupt signal
	// which will immediately exit gitleaks
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt)
	go listenForInterrupt(stopChan)
	cmd.Execute()
}

func listenForInterrupt(stopScan chan os.Signal) {
	<-stopScan
	log.Fatal().Msg("Interrupt signal received. Exiting...")
}
