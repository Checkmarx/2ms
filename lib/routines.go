package lib

import "sync"

func ParallelApply[T comparable, K comparable](items []T, f func(item T) (*[]K, error)) *[]K {
	var wg sync.WaitGroup
	results := []K{}
	for _, item := range items {
		wg.Add(1)
		go func(item T) {
			defer wg.Done()
			result, err := f(item)
			if err != nil {
				return
			}
			if result != nil {
				results = append(results, *result...)
			}
		}(item)
	}
	wg.Wait()

	return &results
}
