package secrets

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// https://www.alibabacloud.com/help/en/sdk/alibaba-cloud-api-overview
// https://www.alibabacloud.com/help/en/sdk/product-overview/rpc-mechanism#sectiondiv-y9b-x9s-wvp

func validateAlibaba(secrets pairsByRuleId) {

	accessKeys := secrets["alibaba-access-key-id"]
	secretKeys := secrets["alibaba-secret-key"]

	for _, accessKey := range accessKeys {
		for _, secretKey := range secretKeys {
			status, err := alibabaRequest(accessKey.Value, secretKey.Value)
			if err != nil {
				log.Warn().Err(err).Str("service", "alibaba").Msg("Failed to validate secret")
			}
			accessKey.ValidationStatus = status
			secretKey.ValidationStatus = status

		}
	}
}

func alibabaRequest(accessKey, secretKey string) (validationResult, error) {
	req, err := http.NewRequest("GET", "https://ecs.aliyuncs.com/", nil)
	if err != nil {
		return Unknown, err
	}

	// Workaround for gitleaks returns the key ends with "
	accessKey = strings.TrimSuffix(accessKey, "\"")
	secretKey = strings.TrimSuffix(secretKey, "\"")

	params := req.URL.Query()
	params.Add("AccessKeyId", accessKey)
	params.Add("Action", "DescribeRegions")
	params.Add("SignatureMethod", "HMAC-SHA1")
	params.Add("SignatureNonce", strconv.FormatInt(time.Now().UnixNano(), 10))
	params.Add("SignatureVersion", "1.0")
	params.Add("Timestamp", time.Now().UTC().Format(time.RFC3339))
	params.Add("Version", "2014-05-26")

	stringToSign := "GET&%2F&" + url.QueryEscape(params.Encode())
	hmac := hmac.New(sha1.New, []byte(secretKey+"&"))
	hmac.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(hmac.Sum(nil))

	params.Add("Signature", signature)
	req.URL.RawQuery = params.Encode()

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return Unknown, err
	}
	log.Debug().Str("service", "alibaba").Int("status_code", resp.StatusCode)

	// If the access key is invalid, the response will be 404
	// If the secret key is invalid, the response will be 400 along with other signautre Errors
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusBadRequest {
		return Revoked, nil
	}

	if resp.StatusCode == http.StatusOK {
		return Valid, nil
	}

	err = fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	return Unknown, err
}
