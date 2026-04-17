package main

import (
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"

	"github.com/checkmarx/2ms/v5/cmd"
	"github.com/checkmarx/2ms/v5/lib/utils"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Logger = utils.CreateLogger(zerolog.InfoLevel)

	// Start pprof server for profiling
	go func() {
		log.Info().Msg("Starting pprof server on :6060")
		if err := http.ListenAndServe(":6060", nil); err != nil {
			log.Error().Err(err).Msg("pprof server failed")
		}
	}()

	// this block sets up a go routine to listen for an interrupt signal
	// which will immediately exit gitleaks
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt)
	go listenForInterrupt(stopChan)

	cmd.Exit(cmd.Execute())
}

func listenForInterrupt(stopScan chan os.Signal) {
	<-stopScan
	log.Error().Msg("Interrupt signal received. Exiting...")
	os.Exit(1)
}
