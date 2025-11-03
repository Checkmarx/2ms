package ruledefine

var flickrAccessTokenRegex = generateSemiGenericRegex(
	[]string{"flickr"}, AlphaNumeric("32"), true).String()

func FlickrAccessToken() *Rule {
	return &Rule{
		RuleID:      "6ee4f7a1-196f-47ad-b0e9-015dfeb0258f",
		Description: "Discovered a Flickr Access Token, posing a risk of unauthorized photo management and potential data leakage.",
		RuleName:    "Flickr-Access-Token",
		Regex:       flickrAccessTokenRegex,
		Keywords: []string{
			"flickr",
		},
		Severity:        "High",
		Tags:            []string{TagAccessToken},
		ScoreParameters: ScoreParameters{Category: CategoryPhotoSharing, RuleType: 4},
	}
}
