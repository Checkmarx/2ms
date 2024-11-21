package cmd

import (
	"sync"

	"github.com/checkmarx/2ms/engine"
	"github.com/checkmarx/2ms/engine/extra"
)

func processItems(engine *engine.Engine, pluginName string) {
	defer channels.WaitGroup.Done()

	wgItems := &sync.WaitGroup{}
	for item := range channels.Items {
		report.TotalItemsScanned++
		wgItems.Add(1)
		go engine.Detect(item, secretsChan, wgItems, pluginName)
	}
	wgItems.Wait()
	close(secretsChan)
}

func processSecrets() {
	defer channels.WaitGroup.Done()

	for secret := range secretsChan {
		report.TotalSecretsFound++
		secretsExtrasChan <- secret
		if validateVar {
			validationChan <- secret
		} else {
			cvssScoreChan <- secret
		}
		report.Results[secret.ID] = append(report.Results[secret.ID], secret)
	}
	close(secretsExtrasChan)
	close(validationChan)
	close(cvssScoreChan)
}

func processSecretsExtras() {
	defer channels.WaitGroup.Done()

	wgExtras := &sync.WaitGroup{}
	for secret := range secretsExtrasChan {
		wgExtras.Add(1)
		go extra.AddExtraToSecret(secret, wgExtras)
	}
	wgExtras.Wait()
}

func processValidation(engine *engine.Engine) {
	defer channels.WaitGroup.Done()

	wgValidation := &sync.WaitGroup{}
	for secret := range validationChan {
		wgValidation.Add(1)
		go func() {
			wgValidation.Done()
			engine.RegisterForValidation(secret)
			cvssScoreChan <- secret
		}()
	}
	wgValidation.Wait()

	engine.Validate()
}

func processScore(engine *engine.Engine) {
	defer channels.WaitGroup.Done()

	wgScore := &sync.WaitGroup{}
	for secret := range cvssScoreChan {
		wgScore.Add(1)
		go engine.Score(secret, validateVar, wgScore)
	}
	wgScore.Wait()
}
