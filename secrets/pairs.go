package secrets

import (
	"sync"
)

type pairsByRuleId map[string][]*Secret
type pairsBySource map[string]pairsByRuleId
type pairsByGeneralKey map[string]pairsBySource

type pairsCollector struct {
	pairs pairsByGeneralKey
}

func newPairsCollector() *pairsCollector {
	return &pairsCollector{pairs: make(pairsByGeneralKey)}
}

func (p *pairsCollector) addIfNeeded(secret *Secret) bool {
	generalKey, ok := ruleToGeneralKey[secret.RuleID]
	if !ok {
		return false
	}

	if _, ok := p.pairs[generalKey]; !ok {
		p.pairs[generalKey] = make(pairsBySource)
	}
	if _, ok := p.pairs[generalKey][secret.Source]; !ok {
		p.pairs[generalKey][secret.Source] = make(pairsByRuleId)
	}
	if _, ok := p.pairs[generalKey][secret.Source][secret.RuleID]; !ok {
		p.pairs[generalKey][secret.Source][secret.RuleID] = make([]*Secret, 0)
	}

	p.pairs[generalKey][secret.Source][secret.RuleID] = append(p.pairs[generalKey][secret.Source][secret.RuleID], secret)
	return true
}

func (p *pairsCollector) validate(generalKey string, rulesById pairsByRuleId, wg *sync.WaitGroup) {
	defer wg.Done()
	generalKeyToValidation[generalKey](rulesById)
}

type pairsValidationFunc func(pairsByRuleId)

var generalKeyToValidation = map[string]pairsValidationFunc{
	"alibaba": validateAlibaba,
}

var generalKeyToRules = map[string][]string{
	"alibaba": {"alibaba-access-key-id", "alibaba-secret-key"},
}

func generateRuleToGeneralKey() map[string]string {
	ruleToGeneralKey := make(map[string]string)
	for key, rules := range generalKeyToRules {
		for _, rule := range rules {
			ruleToGeneralKey[rule] = key
		}
	}
	return ruleToGeneralKey
}

var ruleToGeneralKey = generateRuleToGeneralKey()
