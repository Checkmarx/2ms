package cmd

import (
	"context"

	"github.com/checkmarx/2ms/v4/engine"
	"github.com/checkmarx/2ms/v4/engine/extra"
	"golang.org/x/sync/errgroup"
)

func ProcessItems(engineInstance engine.IEngine, pluginName string) {
	defer Channels.WaitGroup.Done()

	processItems(engineInstance, pluginName)

	engineInstance.GetFileWalkerWorkerPool().Wait()
	// TODO: refactor this so we don't need to finish work of processing items
	// in order to continue the next step of the pipeline
	close(SecretsChan)
}

// processItems uses the engine's worker pool
func processItems(eng engine.IEngine, pluginName string) {
	ctx := context.Background()
	pool := eng.GetFileWalkerWorkerPool()

	// Process items
	for item := range Channels.Items {
		Report.TotalItemsScanned++

		// Create task based on plugin type
		var task workerpool.Task
		switch pluginName {
		case "filesystem":
			task = func(context.Context) error {
				return eng.DetectFile(ctx, item, SecretsChan)
			}
		default:
			task = func(context.Context) error {
				return eng.DetectFragment(item, SecretsChan, pluginName)
			}
		}

		if err := pool.Submit(task); err != nil {
			Channels.Errors <- err
			break
		}
	}
	pool.CloseQueue()
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
