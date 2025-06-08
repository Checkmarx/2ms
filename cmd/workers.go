package cmd

import (
	"context"
	"sync"

	"github.com/checkmarx/2ms/v3/engine"
	"github.com/checkmarx/2ms/v3/engine/extra"
	"github.com/checkmarx/2ms/v3/lib/secrets"
	"golang.org/x/sync/errgroup"
)

func ProcessItems(engineInstance engine.IEngine, pluginName string) {
	defer Channels.WaitGroup.Done()

	g, ctx := errgroup.WithContext(context.Background())
	for item := range Channels.Items {
		Report.TotalItemsScanned++
		item := item

		switch pluginName {
		case "filesystem":
			g.Go(func() error {
				return engineInstance.DetectFile(ctx, item, SecretsChan)
			})
		default:
			g.Go(func() error {
				return engineInstance.DetectFragment(item, SecretsChan, pluginName)
			})
		}
	}

	if err := g.Wait(); err != nil {
		Channels.Errors <- err
	}
	close(SecretsChan)
}

func ProcessSecrets() {
	defer Channels.WaitGroup.Done()

	for secret := range SecretsChan {
		Report.TotalSecretsFound++
		SecretsExtrasChan <- secret
		if validateVar {
			ValidationChan <- secret
		} else {
			CvssScoreWithoutValidationChan <- secret
		}
		Report.Results[secret.ID] = append(Report.Results[secret.ID], secret)
	}
	close(SecretsExtrasChan)
	close(ValidationChan)
	close(CvssScoreWithoutValidationChan)
}

func ProcessSecretsWithValidation() {
	defer Channels.WaitGroup.Done()

	for secret := range SecretsChan {
		Report.TotalSecretsFound++
		SecretsExtrasChan <- secret
		ValidationChan <- secret
		Report.Results[secret.ID] = append(Report.Results[secret.ID], secret)
	}
	close(SecretsExtrasChan)
	close(ValidationChan)
	close(CvssScoreWithoutValidationChan)
}

func ProcessSecretsExtras() {
	defer Channels.WaitGroup.Done()

	wgExtras := &sync.WaitGroup{}
	for secret := range SecretsExtrasChan {
		wgExtras.Add(1)
		go extra.AddExtraToSecret(secret, wgExtras)
	}
	wgExtras.Wait()
}

func ProcessValidationAndScoreWithValidation(engine engine.IEngine) {
	defer Channels.WaitGroup.Done()

	wgValidation := &sync.WaitGroup{}
	for secret := range ValidationChan {
		wgValidation.Add(2)
		go func(secret *secrets.Secret, wg *sync.WaitGroup) {
			engine.RegisterForValidation(secret, wg)
			engine.Score(secret, true, wg)
		}(secret, wgValidation)
	}
	wgValidation.Wait()

	engine.Validate()
}

func ProcessScoreWithoutValidation(engine engine.IEngine) {
	defer Channels.WaitGroup.Done()

	wgScore := &sync.WaitGroup{}
	for secret := range CvssScoreWithoutValidationChan {
		wgScore.Add(1)
		go engine.Score(secret, false, wgScore)
	}
	wgScore.Wait()
}
