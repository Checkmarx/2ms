package extra

import (
	"sync"
)

type NamedMutex struct {
	mutexes sync.Map
}

func (n *NamedMutex) Lock(key string) {
	mu, _ := n.mutexes.LoadOrStore(key, &sync.Mutex{})
	mu.(*sync.Mutex).Lock()
}

func (n *NamedMutex) Unlock(key string) {
	mu, ok := n.mutexes.Load(key)
	if ok {
		mu.(*sync.Mutex).Unlock()
	}
}
