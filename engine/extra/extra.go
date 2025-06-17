package extra

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/checkmarx/2ms/v3/lib/secrets"
)

type addExtraFunc = func(*secrets.Secret) interface{}

var ruleIDToFunction = map[string]addExtraFunc{
	"jwt": addExtraJWT,
}

func AddExtraToSecret(secret *secrets.Secret) {
	if addExtra, ok := ruleIDToFunction[secret.RuleID]; ok {
		extraData := addExtra(secret)
		if extraData != nil && extraData != "" {
			UpdateExtraField(secret, "secretDetails", extraData)
		}
	}
}

var mtxs = &NamedMutex{}

func UpdateExtraField(secret *secrets.Secret, extraName string, extraData interface{}) {
	mtxs.Lock(secret.ID)
	defer mtxs.Unlock(secret.ID)

	if secret.ExtraDetails == nil {
		secret.ExtraDetails = make(map[string]interface{})
	}
	secret.ExtraDetails[extraName] = extraData
}

func addExtraJWT(secret *secrets.Secret) interface{} {
	tokenString := secret.Value

	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return "Invalid JWT token"
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Sprintf("Failed to decode JWT payload: %s", err)
	}

	var claims map[string]interface{}
	err = json.Unmarshal(payload, &claims)
	if err != nil {
		return fmt.Sprintf("Failed to unmarshal JWT payload: %s", string(payload))
	}

	return claims
}
