package cmd

import (
	"github.com/checkmarx/2ms/lib/secrets"
	"sync"

	"github.com/checkmarx/2ms/engine"
	"github.com/checkmarx/2ms/engine/extra"
)

func ProcessItems(engine *engine.Engine, pluginName string) {
	defer Channels.WaitGroup.Done()

	wgItems := &sync.WaitGroup{}
	for item := range Channels.Items {
		report.TotalItemsScanned++
		wgItems.Add(1)
		go engine.Detect(item, secretsChan, wgItems, pluginName, Channels.Errors)
	}
	wgItems.Wait()
	close(secretsChan)
}

func ProcessSecrets() {
	defer Channels.WaitGroup.Done()

	for secret := range secretsChan {
		report.TotalSecretsFound++
		secretsExtrasChan <- secret
		if validateVar {
			validationChan <- secret
		} else {
			cvssScoreWithoutValidationChan <- secret
		}
		report.Results[secret.ID] = append(report.Results[secret.ID], secret)
	}
	close(secretsExtrasChan)
	close(validationChan)
	close(cvssScoreWithoutValidationChan)
}

func ProcessSecretsExtras() {
	defer Channels.WaitGroup.Done()

	wgExtras := &sync.WaitGroup{}
	for secret := range secretsExtrasChan {
		wgExtras.Add(1)
		go extra.AddExtraToSecret(secret, wgExtras)
	}
	wgExtras.Wait()
}

func ProcessValidationAndScoreWithValidation(engine *engine.Engine) {
	defer Channels.WaitGroup.Done()

	wgValidation := &sync.WaitGroup{}
	for secret := range validationChan {
		wgValidation.Add(2)
		go func(secret *secrets.Secret, wg *sync.WaitGroup) {
			engine.RegisterForValidation(secret, wg)
			engine.Score(secret, true, wg)
		}(secret, wgValidation)
	}
	wgValidation.Wait()

	engine.Validate()
}

func ProcessScoreWithoutValidation(engine *engine.Engine) {
	defer Channels.WaitGroup.Done()

	wgScore := &sync.WaitGroup{}
	for secret := range cvssScoreWithoutValidationChan {
		wgScore.Add(1)
		go engine.Score(secret, false, wgScore)
	}
	wgScore.Wait()
}
