package cmd

import (
	"context"

	"github.com/checkmarx/2ms/v4/engine"
	"github.com/checkmarx/2ms/v4/engine/extra"
	"github.com/checkmarx/2ms/v4/internal/workerpool"
)

func ProcessItems(engineInstance engine.IEngine, pluginName string) {
	defer Channels.WaitGroup.Done()
	processItems(engineInstance, pluginName)

	pool := engineInstance.GetDetectorWorkerPool()
	pool.Wait()
	pool.CloseQueue()
	close(SecretsChan)
}

// processItems uses the engine's worker pool
func processItems(eng engine.IEngine, pluginName string) {
	ctx := context.Background()
	pool := eng.GetDetectorWorkerPool()

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
	for secret := range SecretsExtrasChan {
		extra.AddExtraToSecret(secret)
	}
}

func ProcessValidationAndScoreWithValidation(engine engine.IEngine) {
	defer Channels.WaitGroup.Done()
	for secret := range ValidationChan {
		engine.RegisterForValidation(secret)
		engine.Score(secret, true)
	}
	engine.Validate()
}

func ProcessScoreWithoutValidation(engine engine.IEngine) {
	defer Channels.WaitGroup.Done()
	for secret := range CvssScoreWithoutValidationChan {
		engine.Score(secret, false)
	}
}
