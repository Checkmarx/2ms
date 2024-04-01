package extra

import "github.com/checkmarx/2ms/lib/secrets"

type addExtraFunc = func(*secrets.Secret)

var ruleIDToFunction = map[string]addExtraFunc{}

func AddExtraToSecret(secret *secrets.Secret) {
	if addExtra, ok := ruleIDToFunction[secret.RuleID]; ok {
		addExtra(secret)
	}
}

var mtxs = &NamedMutex{}

func UpdateExtraField(secret *secrets.Secret, extraName string, extraData interface{}) {
	mtxs.Lock(secret.ID)
	defer mtxs.Unlock(secret.ID)

	secret.ExtraDetails[extraName] = extraData
}
