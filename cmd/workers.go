package cmd

import (
	"github.com/checkmarx/2ms/engine"
	"github.com/checkmarx/2ms/engine/extra"
	"github.com/checkmarx/2ms/lib/secrets"
	"sync"
)

func ProcessItems(engine *engine.Engine, pluginName string) { //fechou
	defer Channels.WaitGroup.Done()
	wgItems := &sync.WaitGroup{}
	for item := range Channels.Items {
		Report.TotalItemsScanned++
		wgItems.Add(1)
		go engine.Detect(item, secretsChan, wgItems, pluginName, Channels.Errors)
	}
	wgItems.Wait()
	close(secretsChan)
}

func ProcessSecrets() { //fechou
	defer Channels.WaitGroup.Done()

	for secret := range secretsChan {
		Report.TotalSecretsFound++
		secretsExtrasChan <- secret
		if validateVar {
			validationChan <- secret
		} else {
			cvssScoreWithoutValidationChan <- secret
		}
		Report.Results[secret.ID] = append(Report.Results[secret.ID], secret)
	}
	close(secretsExtrasChan)
	close(validationChan)
	close(cvssScoreWithoutValidationChan)
}

func ProcessSecretsExtras() { //fechou
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

func ProcessScoreWithoutValidation(engine *engine.Engine) { //fechou
	defer Channels.WaitGroup.Done()

	wgScore := &sync.WaitGroup{}
	for secret := range cvssScoreWithoutValidationChan {
		wgScore.Add(1)
		go engine.Score(secret, false, wgScore)
	}
	wgScore.Wait()
}
