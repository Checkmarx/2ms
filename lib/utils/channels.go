package utils

import "sync"

func BindChannels[T any](source <-chan T, dest chan<- T, wg *sync.WaitGroup) {
	if wg != nil {
		defer wg.Done()
	}
	for item := range source {
		dest <- item
	}
}
