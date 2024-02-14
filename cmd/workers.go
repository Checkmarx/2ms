package cmd

import (
	"sync"

	"github.com/checkmarx/2ms/secrets"
)

func processItems(detector *secrets.Secrets) {
	defer channels.WaitGroup.Done()

	wgItems := &sync.WaitGroup{}
	for item := range channels.Items {
		report.TotalItemsScanned++
		wgItems.Add(1)
		go detector.Detect(item, secretsChan, wgItems, ignoreVar)
	}
	wgItems.Wait()
	close(secretsChan)
}

func processSecrets() {
	defer channels.WaitGroup.Done()

	for secret := range secretsChan {
		report.TotalSecretsFound++
		report.Results[secret.ID] = append(report.Results[secret.ID], secret)
	}
}
