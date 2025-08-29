package benches

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/checkmarx/2ms/v4/engine"
	"github.com/checkmarx/2ms/v4/internal/workerpool"
	"github.com/checkmarx/2ms/v4/lib/reporting"
	"github.com/checkmarx/2ms/v4/lib/secrets"
	"github.com/checkmarx/2ms/v4/plugins"
	"github.com/rs/zerolog"
)

var (
	benchmarkDir string
	allMockItems []*mockItem
	maxItems     = 10000
)

type mockItem struct {
	content *string
	id      string
	source  string
}

func (i *mockItem) GetContent() *string {
	return i.content
}

func (i *mockItem) GetID() string {
	return i.id
}

func (i *mockItem) GetSource() string {
	return i.source
}

func (i *mockItem) GetGitInfo() *plugins.GitInfo {
	return nil
}

// getFileExtension returns the appropriate file extension based on content template index
func getFileExtension(templateIndex int) string {
	if templateIndex < len(FileExtensions) {
		return FileExtensions[templateIndex]
	}
	return ".txt"
}

// TestMain sets up and tears down benchmark files
func TestMain(m *testing.M) {
	err := setupBenchmarkFiles()
	if err != nil {
		fmt.Printf("Failed to setup benchmark files: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()

	os.RemoveAll(benchmarkDir)

	os.Exit(code)
}

// setupBenchmarkFiles creates benchmark files once
func setupBenchmarkFiles() error {
	// Create temporary directory
	var err error
	benchmarkDir, err = os.MkdirTemp("", "benchmark_files_*")
	if err != nil {
		return fmt.Errorf("failed to create benchmark directory: %w", err)
	}

	fmt.Printf("Creating %d benchmark files in %s...\n", maxItems, benchmarkDir)
	allMockItems = make([]*mockItem, maxItems)
	for j := range maxItems {
		var content string
		var ext string

		// 60% of files contain secrets, 40% don't
		if j%10 < 6 {
			// Secret files: use only secret templates (0-4)
			templateIndex := j % (len(ContentTemplates) - 1)
			template := ContentTemplates[templateIndex]
			secret := SecretPatterns[j%len(SecretPatterns)]
			content = fmt.Sprintf(template, secret)
			ext = getFileExtension(templateIndex)
		} else {
			// No-secret files: always use Go template
			content = ContentTemplates[len(ContentTemplates)-1]
			ext = ".go"
		}

		// Add some padding to simulate larger files
		padding := generateRealisticPadding(j)
		content += padding

		// Write content to actual file
		filename := fmt.Sprintf("file_%d%s", j, ext)
		filePath := filepath.Join(benchmarkDir, filename)
		err := os.WriteFile(filePath, []byte(content), 0644)
		if err != nil {
			return fmt.Errorf("failed to write file %s: %w", filePath, err)
		}

		allMockItems[j] = &mockItem{
			content: &content,
			id:      fmt.Sprintf("file_%d", j),
			source:  filePath,
		}
	}

	fmt.Printf("Successfully created %d benchmark files\n", maxItems)
	return nil
}

// BenchmarkProcessItems benchmarks ProcessItems with realistic content that includes actual secrets
func BenchmarkProcessItems(b *testing.B) {
	nCPU := runtime.GOMAXPROCS(0)
	fmt.Println("nCPU", nCPU)
	workerSizes := []int{nCPU / 2, nCPU, nCPU * 2, nCPU * 4, nCPU * 8, nCPU * 16, nCPU * 32}
	itemSizes := []int{50, 100, 500, 1000, 10000}

	zerolog.SetGlobalLevel(zerolog.ErrorLevel)

	for _, workers := range workerSizes {
		for _, items := range itemSizes {
			b.Run(fmt.Sprintf("realistic_workers_%d_items_%d", workers, items), func(b *testing.B) {
				// Use subset of pre-created mock items from TestMain
				mockItems := allMockItems[:items]

				b.ResetTimer()
				for range b.N {
					// Create engine for each iteration
					engineTest, err := engine.Init(&engine.EngineConfig{
						DetectorWorkerPoolSize: workers,
					})
					if err != nil {
						b.Fatal(err)
					}

					// Create fresh channels
					itemsChan := make(chan plugins.ISourceItem, items)
					secretsChan := make(chan *secrets.Secret, items*2) // Larger buffer for found secrets
					report := reporting.Init()
					wg := &sync.WaitGroup{}
					wg.Add(1)

					go func() {
						defer wg.Done()
						processItemsLocal(engineTest, "filesystem", itemsChan, secretsChan, report)
					}()

					// Send items
					for _, item := range mockItems {
						itemsChan <- item
					}
					close(itemsChan)

					wg.Wait()
					close(secretsChan)

					secretsFound := 0
					for range secretsChan {
						secretsFound++
					}

					_ = engineTest.Shutdown()
				}
			})
		}
	}
}

// generateRealisticPadding generates padding content to simulate realistic file sizes
func generateRealisticPadding(seed int) string {
	// Size categories: small (1KB), medium (10KB), large (50KB)
	sizes := []int{1024, 10240, 51200}
	sizeIndex := seed % len(sizes)
	targetSize := sizes[sizeIndex]

	var builder strings.Builder
	currentSize := 0
	patternIndex := 0

	for currentSize < targetSize {
		pattern := PaddingPatterns[patternIndex%len(PaddingPatterns)]
		builder.WriteString(pattern)
		currentSize += len(pattern)
		patternIndex++
	}

	return builder.String()
}

// Local version of processItems that doesn't use global variables
func processItemsLocal(eng engine.IEngine, pluginName string, items chan plugins.ISourceItem, secrets chan *secrets.Secret, report *reporting.Report) {
	ctx := context.Background()
	pool := eng.GetDetectorWorkerPool()

	for item := range items {
		report.TotalItemsScanned++

		var task workerpool.Task
		switch pluginName {
		case "filesystem":
			task = func(context.Context) error {
				return eng.DetectFile(ctx, item, secrets)
			}
		default:
			task = func(context.Context) error {
				return eng.DetectFragment(item, secrets, pluginName)
			}
		}

		if err := pool.Submit(task); err != nil {
			// Handle error appropriately
			break
		}
	}
	pool.Wait()
	pool.CloseQueue()
}
