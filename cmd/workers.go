package cmd

import (
	"context"

	"github.com/checkmarx/2ms/v3/engine"
	"github.com/checkmarx/2ms/v3/engine/extra"
	"github.com/checkmarx/2ms/v3/internal/workerpool"
	"golang.org/x/sync/errgroup"
)

func ProcessItems(engineInstance engine.IEngine, pluginName string) {
	defer Channels.WaitGroup.Done()

	// Check if engine has a worker pool
	if eng, ok := engineInstance.(*engine.Engine); ok && eng.HasWorkerPool() {
		processItemsWithPool(eng, pluginName)
	} else {
		processItemsWithErrgroup(engineInstance, pluginName)
	}

	close(SecretsChan)
}

// processItemsWithPool uses the engine's worker pool
func processItemsWithPool(eng *engine.Engine, pluginName string) {
	ctx := context.Background()
	pool := eng.GetWorkerPool()

	// Process items
	for item := range Channels.Items {
		Report.TotalItemsScanned++
		item := item // capture loop variable

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

// processItemsWithErrgroup uses the original errgroup approach
func processItemsWithErrgroup(engineInstance engine.IEngine, pluginName string) {
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
