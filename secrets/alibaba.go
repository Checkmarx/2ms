package secrets

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"io"
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
			statusCode, err := alibabaRequest(accessKey.Value, secretKey.Value)
			if err != nil {
				log.Warn().Err(err).Str("service", "alibaba").Msg("Failed to validate secret")
				accessKey.Validation = Unknown
				secretKey.Validation = Unknown
				continue
			}

			if statusCode == http.StatusOK {
				accessKey.Validation = Valid
				secretKey.Validation = Valid
			} else {
				accessKey.Validation = Revoked
				secretKey.Validation = Revoked
			}
		}
	}
}

func alibabaRequest(accessKey, secretKey string) (int, error) {
	req, err := http.NewRequest("GET", "https://ecs.aliyuncs.com/", nil)
	if err != nil {
		return 0, err
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
		return 0, err
	}

	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		log.Panic().
			Str("access_key", accessKey).
			Str("service", "alibaba").
			Int("status_code", resp.StatusCode).
			Msgf("Failed to validate secret %s", body)
	}

	log.Debug().Str("service", "alibaba").Int("status_code", resp.StatusCode).Msg("Validated secret")
	return resp.StatusCode, nil
}
