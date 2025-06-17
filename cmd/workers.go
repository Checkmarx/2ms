package cmd

import (
	"context"

	"github.com/checkmarx/2ms/v3/engine"
	"github.com/checkmarx/2ms/v3/engine/extra"
	"golang.org/x/sync/errgroup"
)

func ProcessItems(engineInstance engine.IEngine, pluginName string) {
	defer Channels.WaitGroup.Done()

	g, ctx := errgroup.WithContext(context.Background())
	g.SetLimit(1000)
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

	g := errgroup.Group{}
	g.SetLimit(10)
	for secret := range SecretsExtrasChan {
		g.Go(func() error {
			extra.AddExtraToSecret(secret)
			return nil
		})
	}
	_ = g.Wait()
}

func ProcessValidationAndScoreWithValidation(engine engine.IEngine) {
	defer Channels.WaitGroup.Done()

	g := errgroup.Group{}
	g.SetLimit(10)
	for secret := range ValidationChan {
		g.Go(func() error {
			engine.RegisterForValidation(secret)
			engine.Score(secret, true)
			return nil
		})
	}
	_ = g.Wait()
	engine.Validate()
}

func ProcessScoreWithoutValidation(engine engine.IEngine) {
	defer Channels.WaitGroup.Done()

	g := errgroup.Group{}
	g.SetLimit(10)
	for secret := range CvssScoreWithoutValidationChan {
		g.Go(func() error {
			engine.Score(secret, false)
			return nil
		})
	}
	_ = g.Wait()
}
