package validation

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // SHA1 is required by Alibaba API for HMAC-SHA1 signatures
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/checkmarx/2ms/v5/lib/secrets"
	"github.com/rs/zerolog/log"
)

// https://www.alibabacloud.com/help/en/sdk/alibaba-cloud-api-overview
// https://www.alibabacloud.com/help/en/sdk/product-overview/rpc-mechanism#sectiondiv-y9b-x9s-wvp

func validateAlibaba(secretsPairs pairsByRuleId) {
	accessKeys := secretsPairs["alibaba-access-key-id"]
	secretKeys := secretsPairs["alibaba-secret-key"]

	for _, accessKey := range accessKeys {
		accessKey.ValidationStatus = secrets.UnknownResult

		for _, secretKey := range secretKeys {
			status, err := alibabaRequest(accessKey.Value, secretKey.Value)
			if err != nil {
				log.Warn().Err(err).Str("service", "alibaba").Msg("Failed to validate secret")
			}

			secretKey.ValidationStatus = status
			if accessKey.ValidationStatus.CompareTo(status) > 0 {
				accessKey.ValidationStatus = status
			}
		}
	}
}

func alibabaRequest(accessKey, secretKey string) (secrets.ValidationResult, error) {
	req, err := http.NewRequestWithContext(context.Background(), "GET", "https://ecs.aliyuncs.com/", http.NoBody)
	if err != nil {
		return secrets.UnknownResult, err
	}

	// Workaround for gitleaks returns the key ends with "
	// https://github.com/gitleaks/gitleaks/pull/1350
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
		return secrets.UnknownResult, err
	}
	defer resp.Body.Close()
	log.Debug().Str("service", "alibaba").Int("status_code", resp.StatusCode)

	// If the access key is invalid, the response will be 404
	// If the secret key is invalid, the response will be 400 along with other signautre Errors
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusBadRequest {
		return secrets.InvalidResult, nil
	}

	if resp.StatusCode == http.StatusOK {
		return secrets.ValidResult, nil
	}

	err = fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	return secrets.UnknownResult, err
}
