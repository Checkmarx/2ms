package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCurlBasicAuth(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "CurlBasicAuth validation",
			truePositives: []string{
				// short
				`curl --cacert ca.crt -u elastic:P@ssw0rd$1 https://localhost:9200`, // same lines, no quotes
				`sh-5.0$ curl -k -X POST https://infinispan:11222/rest/v2/caches/default/hello \
  -H 'Content-type: text/plain' \
  -d 'world' \
  -u developer:yqDVtkqPECriaLRi`, // different line
				`curl -u ":d2LkV78zLx!t" https://localhost:9200`, // empty username
				`curl -u "d2LkV78zLx!t:" https://localhost:9200`, // empty password

				// long
				`curl -sw '%{http_code}' -X POST --user  'johns:h0pk1ns~21s' $GItHUB_API_URL/$GIT_COMMIT --data`,
				`curl --user roger23@gmail.com:pQ9wTxu4Fg https://www.dropbox.com/cli_link?host_id=abcdefg -v`, // same line, no quotes
				`curl -s --user 'api:d2LkV78zLx!t' \
    https://api.mailgun.net/v2/sandbox91d3515882ecfaa1c65be642.mailgun.org/messages`, // same line, single quotes
				`curl -s -v --user "j.smith:dB2yF6@qL9vZm1P#4J" "https://api.contoso.org/user/me"`, // same line, double quotes
				`curl -X POST --user "{acd3c08b-74e8-4f44-a2d0-80694le24f46}":"{ZqL5kVrX1n8tA2}" --header "Accept: application/json" --data "{\"text\":\"Hello, world\",\"source\":\"en\",\"target\":\"es\"}" https://gateway.watsonplatform.net/language-translator/api`,
				`curl --user kevin:'pRf7vG2h1L8nQkW9' -iX PATCH -H "Content-Type: application/json" -d`, // same line, mixed quoting
				`$ curl https://api.dropbox.com/oauth2/token \
  --user c28wlsosanujy2z:qgsnai0xokrw4j1 --data grant_type=authorization_code`, // different line

				// TODO
				//`     curl -s --insecure --url "imaps://whatever.imap.server" --user\
				//"myuserid:mypassword" --request "STATUS INBOX (UNSEEN)"`,
			},
			falsePositives: []string{
				// short
				`curl -i -u 'test:test'`,
				`   curl -sL --user "$1:$2" "$3" > "$4"`,                      // environment variable
				`curl -u <user:password> https://test.com/endpoint`,           // placeholder
				`curl --user neo4j:[PASSWORD] http://[IP]:7474/db/data/`,      // placeholder
				`curl -u "myusername" http://localhost:15130/api/check_user/`, // no password
				`curl -u username:token`,
				`curl -u "${_username}:${_password}"`,
				`curl -u "${username}":"${password}"`,
				`curl -k -X POST -I -u "SRVC_JENKINS:${APPID}"`,
				`curl -u ":" https://localhost:9200`, // empty username and password

				// long
				`curl -sw '%{http_code}' -X POST --user '$USERNAME:$PASSWORD' $GItHUB_API_URL/$GIT_COMMIT --data`,
				`curl --user "xxx:yyy"`,
				`           curl -sL --user "$GITHUB_USERNAME:$GITHUB_PASSWORD" "$GITHUB_URL" > "$TESTS_PATH"`, // environment variable
				// variable interpolation
				`curl --silent --fail {{- if and $.Values.username $.Values.password }} --user "{{ $.Values.username }}:{{ $.Values.password }}"`,
				`curl -XGET -i -u "${{ env.ELK_ID }}:${{ build.env.ELK_PASS }}"`,
				`curl -XGET -i -u "${{needs.vault.outputs.account_id}}:${{needs.vault.outputs.account_password}}"`,
				`curl -XGET -i -u "${{ steps.vault.outputs.account_id }}:${{ steps.vault.outputs.account_password }}"`,
				`curl -X POST --user "$(cat ./login.txt):$(cat ./password.txt)"`,                                                                                           // command
				`curl http://127.0.0.1:5000/file --user user:pass --digest        # digest auth`,                                                                           // placeholder
				`   curl -X GET --insecure --user "username:password" \`,                                                                                                   // placeholder
				`curl --silent --insecure --user ${f5user}:${f5pass} \`,                                                                                                    // placeholder
				`curl --insecure --ssl-reqd "smtps://smtp.gmail.com" --mail-from "src@gmail.com" --mail-rcpt "dst@gmail.com" --user "src@gmail.com" --upload-file out.txt`, // no password

				// different command
				`#HTTP command line test
curl -X POST -H "Content-Type: application/json" -d '{"id":12345,"geo":{"latitude":28.50,"longitude":-81.14}}' http://<ip>:8080/serve

#UDP command line test
echo -n '{"type":"serve","channel":"/","data":{"site_id":8,"post_id":12345,"geo":{"lat":28.50,"long":-81.14}}}' >/dev/udp/127.0.0.1/41234

#UDP Listener (for confirmation)
nc -u -l 41234`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(CurlBasicAuth())
			d := createSingleRuleDetector(rule)

			// validate true positives if any specified
			for _, truePositive := range tt.truePositives {
				findings := d.DetectString(truePositive)
				assert.GreaterOrEqual(t, len(findings), 1, fmt.Sprintf("failed to detect true positive: %s", truePositive))
			}

			// validate false positives if any specified
			for _, falsePositive := range tt.falsePositives {
				findings := d.DetectString(falsePositive)
				assert.Equal(t, 0, len(findings), fmt.Sprintf("unexpectedly found false positive: %s", falsePositive))
			}
		})
	}
}
