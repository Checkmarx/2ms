package cmd

import (
	"github.com/checkmarx/2ms/engine"
	"github.com/checkmarx/2ms/engine/extra"
	"golang.org/x/sync/errgroup"
)

func processItems(engine *engine.Engine, pluginName string) {
	defer channels.WaitGroup.Done()

	g := errgroup.Group{}
	g.SetLimit(1000)
	for item := range channels.Items {
		report.TotalItemsScanned++
		g.Go(func() error {
			engine.Detect(item, secretsChan, pluginName, channels.Errors)
			return nil
		})
	}
	g.Wait()
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
			cvssScoreWithoutValidationChan <- secret
		}
		report.Results[secret.ID] = append(report.Results[secret.ID], secret)
	}
	close(secretsExtrasChan)
	close(validationChan)
	close(cvssScoreWithoutValidationChan)
}

func processSecretsExtras() {
	defer channels.WaitGroup.Done()

	g := errgroup.Group{}
	g.SetLimit(10)
	for secret := range secretsExtrasChan {
		g.Go(func() error {
			extra.AddExtraToSecret(secret)
			return nil
		})
	}
	g.Wait()
}

func processValidationAndScoreWithValidation(engine *engine.Engine) {
	defer channels.WaitGroup.Done()

	g := errgroup.Group{}
	g.SetLimit(10)
	for secret := range validationChan {
		g.Go(func() error {
			engine.RegisterForValidation(secret)
			engine.Score(secret, true)
			return nil
		})
	}
	g.Wait()
	engine.Validate()
}

func processScoreWithoutValidation(engine *engine.Engine) {
	defer channels.WaitGroup.Done()

	g := errgroup.Group{}
	g.SetLimit(10)
	for secret := range cvssScoreWithoutValidationChan {
		g.Go(func() error {
			engine.Score(secret, false)
			return nil
		})
	}
	g.Wait()
}
