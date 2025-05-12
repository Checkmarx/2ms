package cmd

import (
	"context"
	"github.com/checkmarx/2ms/engine"
	"github.com/checkmarx/2ms/engine/extra"
	"github.com/checkmarx/2ms/lib/secrets"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
	"sync"
)

func ProcessItems(engineInstance *engine.Engine, pluginName string) {
	defer Channels.WaitGroup.Done()

	g, ctx := errgroup.WithContext(context.Background())
	memoryBudget := chooseMemoryBudget()
	sem := semaphore.NewWeighted(memoryBudget)
	for item := range Channels.Items {
		Report.TotalItemsScanned++
		item := item

		switch pluginName {
		case "filesystem":
			g.Go(func() error {
				return engineInstance.DetectFile(ctx, item, SecretsChan, memoryBudget, sem)
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

func ProcessSecretsExtras() {
	defer Channels.WaitGroup.Done()

	wgExtras := &sync.WaitGroup{}
	for secret := range SecretsExtrasChan {
		wgExtras.Add(1)
		go extra.AddExtraToSecret(secret, wgExtras)
	}
	wgExtras.Wait()
}

func ProcessValidationAndScoreWithValidation(engine *engine.Engine) {
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

func ProcessScoreWithoutValidation(engine *engine.Engine) {
	defer Channels.WaitGroup.Done()

	wgScore := &sync.WaitGroup{}
	for secret := range CvssScoreWithoutValidationChan {
		wgScore.Add(1)
		go engine.Score(secret, false, wgScore)
	}
	wgScore.Wait()
}
