package cmd

import (
	"fmt"
	"github.com/checkmarx/2ms/engine"
	"github.com/checkmarx/2ms/engine/extra"
	"github.com/checkmarx/2ms/lib/secrets"
	"sync"
)

func ProcessItems(engine *engine.Engine, pluginName string) { //fechou
	defer func() {
		Channels.WaitGroup.Done()
		fmt.Println("ProcessItems is done")
	}()
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
	defer func() {
		Channels.WaitGroup.Done()
		fmt.Println("ProcessSecrets is done")
	}()
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
	defer func() {
		Channels.WaitGroup.Done()
		fmt.Println("ProcessSecretsExtras is done")
	}()

	wgExtras := &sync.WaitGroup{}
	for secret := range secretsExtrasChan {
		wgExtras.Add(1)
		go extra.AddExtraToSecret(secret, wgExtras)
	}
	wgExtras.Wait()
}

func ProcessValidationAndScoreWithValidation(engine *engine.Engine) {
	defer func() {
		Channels.WaitGroup.Done()
		fmt.Println("ProcessValidationAndScoreWithValidation is done")
	}()
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
	defer func() {
		Channels.WaitGroup.Done()
		fmt.Println("ProcessScoreWithoutValidation is done")
	}()
	wgScore := &sync.WaitGroup{}
	for secret := range cvssScoreWithoutValidationChan {
		wgScore.Add(1)
		go engine.Score(secret, false, wgScore)
	}
	wgScore.Wait()
}
