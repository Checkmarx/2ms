package rules

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/utils"
	"github.com/zricethezav/gitleaks/v8/cmd/generate/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

// SumoLogicAccessID returns a corrected SumoLogic Access ID rule that fixes the token validation issue.
// This overrides the default GitLeaks SumoLogic rule to fix validation bugs.
func SumoLogicAccessID() *config.Rule {
	// define rule - same as GitLeaks but with corrected validation
	r := config.Rule{
		RuleID:      "sumologic-access-id",
		Description: "Discovered a SumoLogic Access ID, potentially compromising log management services and data analytics integrity.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"(?-i:[Ss]umo|SUMO)"}, "su[a-zA-Z0-9]{12}", false),
		Entropy:     3,
		Keywords: []string{
			"sumo",
		},
	}

	// Fixed validation - use the same pattern as original GitLeaks
	tps := utils.GenerateSampleSecrets("sumo", secrets.NewSecret(`su[a-zA-Z0-9]{12}`))
	tps = append(tps,
		`sumologic.accessId = "su9OL59biWiJu7"`,      // 14 chars: su + 12 alphanumeric
		`sumologic_access_id = "sug5XpdpaoxtOH"`,     // 14 chars: su + 12 alphanumeric
		`export SUMOLOGIC_ACCESSID="suDbJw97o9WVo0"`, // 14 chars: su + 12 alphanumeric
		`SUMO_ACCESS_ID = "suGyI5imvADdvU"`,          // 14 chars: su + 12 alphanumeric
	)

	fps := []string{
		`- (NSNumber *)sumOfProperty:(NSString *)property;`,
		`- (NSInteger)sumOfValuesInRange:(NSRange)range;`,
		`+ (unsigned char)byteChecksumOfData:(id)arg1;`,
		`sumOfExposures = sumOfExposures;`,
		`.si-sumologic.si--color::before { color: #000099; }`,
		`/// Based on the SumoLogic keyword syntax:`,
		`sumologic_access_id         = ""`,
		`SUMOLOGIC_ACCESSID: ${SUMOLOGIC_ACCESSID}`,
		`export SUMOLOGIC_ACCESSID=XXXXXXXXXXXXXX`,
		`sumObj = suGyI5imvADdvU`,
	}

	return utils.Validate(r, tps, fps)
}

// SumoLogicAccessToken returns a corrected SumoLogic Access Token rule that fixes the token validation issue.
// This overrides the default GitLeaks SumoLogic rule to fix validation bugs.
func SumoLogicAccessToken() *config.Rule {
	// define rule - same as GitLeaks but with corrected validation
	r := config.Rule{
		RuleID:      "sumologic-access-token",
		Description: "Uncovered a SumoLogic Access Token, which could lead to unauthorized access to log data and analytics insights.",
		Regex:       utils.GenerateSemiGenericRegex([]string{"(?-i:[Ss]umo|SUMO)"}, utils.AlphaNumeric("64"), true),
		Entropy:     3,
		Keywords: []string{
			"sumo",
		},
	}

	// Fixed validation - use the same pattern as original GitLeaks
	tps := utils.GenerateSampleSecrets("sumo", secrets.NewSecret(utils.AlphaNumeric("64")))
	tps = append(tps,
		`export SUMOLOGIC_ACCESSKEY="3HSa1hQfz6BYzlxf7Yb1WKG3Hyovm56LMFChV2y9LgkRipsXCujcLb5ej3oQUJlx"`, // 64 alphanumeric chars
		`SUMO_ACCESS_KEY: gxq3rJQkS6qovOg9UY2Q70iH1jFZx0WBrrsiAYv4XHodogAwTKyLzvFK4neRN8Dk`,             // 64 alphanumeric chars
		`SUMOLOGIC_ACCESSKEY: 9RITWb3I3kAnSyUolcVJq4gwM17JRnQK8ugRaixFfxkdSl8ys17ZtEL3LotESKB7`,         // 64 alphanumeric chars
		`sumo_access_key = "3Kof2VffNQ0QgYIhXUPJosVlCaQKm2hfpWE6F1fT9YGY74blQBIPsrkCcf1TwKE5"`,          // 64 alphanumeric chars
	)

	fps := []string{
		`#   SUMO_ACCESS_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
		"-e SUMO_ACCESS_KEY=`etcdctl get /sumologic_secret`",
		`SUMO_ACCESS_KEY={SumoAccessKey}`,
		`SUMO_ACCESS_KEY=${SUMO_ACCESS_KEY:=$2}`,
		`sumo_access_key   = "<SUMOLOGIC ACCESS KEY>"`,
		`SUMO_ACCESS_KEY: AbCeFG123`,
		`sumOfExposures = 3Kof2VffNQ0QgYIhXUPJosVlCaQKm2hfpWE6F1fT9YGY74blQBIPsrkCcf1TwKE5;`,
	}

	return utils.Validate(r, tps, fps)
}
