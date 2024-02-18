package secrets

var pairRules = [][]string{
	{"alibaba-access-key-id", "alibaba-secret-key"},
}

func generateAllKeys() map[string]bool {
	allPaired := make(map[string]bool)
	for _, pair := range pairRules {
		for _, key := range pair {
			allPaired[key] = true
		}
	}
	return allPaired
}

var allPaired = generateAllKeys()

var pairedSecrets = make(map[string][]*Secret)
