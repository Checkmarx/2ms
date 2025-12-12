package score

import (
	"math"
	"slices"
	"strings"

	"github.com/checkmarx/2ms/v4/engine/rules/ruledefine"
	"github.com/checkmarx/2ms/v4/lib/secrets"
	"github.com/zricethezav/gitleaks/v8/config"
)

var (
	CategoryScoreMap = map[ruledefine.RuleCategory]uint8{
		ruledefine.CategoryAuthenticationAndAuthorization: 4,
		ruledefine.CategoryCryptocurrencyExchange:         4,
		ruledefine.CategoryFinancialServices:              4,
		ruledefine.CategoryPaymentProcessing:              4,
		ruledefine.CategorySecurity:                       4,
		ruledefine.CategoryAPIAccess:                      3,
		ruledefine.CategoryCICD:                           3,
		ruledefine.CategoryCloudPlatform:                  3,
		ruledefine.CategoryDatabaseAsAService:             3,
		ruledefine.CategoryDevelopmentPlatform:            3,
		ruledefine.CategoryEmailDeliveryService:           3,
		ruledefine.CategoryGeneralOrUnknown:               3,
		ruledefine.CategoryInfrastructureAsCode:           3,
		ruledefine.CategoryPackageManagement:              3,
		ruledefine.CategorySourceCodeManagement:           3,
		ruledefine.CategoryWebHostingAndDeployment:        3,
		ruledefine.CategoryBackgroundProcessingService:    2,
		ruledefine.CategoryCDN:                            2,
		ruledefine.CategoryContentManagementSystem:        2,
		ruledefine.CategoryCustomerSupport:                2,
		ruledefine.CategoryDataAnalytics:                  2,
		ruledefine.CategoryFileStorageAndSharing:          2,
		ruledefine.CategoryIoTPlatform:                    2,
		ruledefine.CategoryMappingAndLocationServices:     2,
		ruledefine.CategoryNetworking:                     2,
		ruledefine.CategoryPhotoSharing:                   2,
		ruledefine.CategorySaaS:                           2,
		ruledefine.CategoryShipping:                       2,
		ruledefine.CategorySoftwareDevelopment:            2,
		ruledefine.CategoryAIAndMachineLearning:           1,
		ruledefine.CategoryApplicationMonitoring:          1,
		ruledefine.CategoryECommercePlatform:              1,
		ruledefine.CategoryMarketingAutomation:            1,
		ruledefine.CategoryNewsAndMedia:                   1,
		ruledefine.CategoryOnlineSurveyPlatform:           1,
		ruledefine.CategoryProjectManagement:              1,
		ruledefine.CategorySearchService:                  1,
		ruledefine.CategorySocialMedia:                    1,
	}

	RuleTypeMaxValue uint8 = 4
)

type scorer struct {
	rulesBaseRiskScore       map[string]float64
	withValidation           bool
	keywords                 map[string]struct{}
	twomsRulesToBeApplied    map[string]ruledefine.Rule
	gitleaksRulesToBeApplied map[string]config.Rule // same rules from twomsRulesToBeApplied, converted to gitleaks format
}

func NewScorer(selectedRules []*ruledefine.Rule, withValidation bool) *scorer {
	twomsRulesToBeApplied := make(map[string]ruledefine.Rule)
	gitleaksRulesToBeApplied := make(map[string]config.Rule)
	rulesBaseRiskScore := make(map[string]float64)
	keywords := make(map[string]struct{})
	for _, rule := range selectedRules {
		twomsRulesToBeApplied[rule.RuleID] = *rule
		gitleaksRulesToBeApplied[rule.RuleID] = *ruledefine.TwomsToGitleaksRule(rule)
		rulesBaseRiskScore[rule.RuleID] = GetBaseRiskScore(rule.Category, rule.ScoreRuleType)
		for _, keyword := range rule.Keywords {
			keywords[strings.ToLower(keyword)] = struct{}{}
		}
	}
	return &scorer{
		rulesBaseRiskScore:       rulesBaseRiskScore,
		withValidation:           withValidation,
		keywords:                 keywords,
		twomsRulesToBeApplied:    twomsRulesToBeApplied,
		gitleaksRulesToBeApplied: gitleaksRulesToBeApplied,
	}
}

func (s *scorer) AssignScoreAndSeverity(secret *secrets.Secret) {
	validationStatus := secrets.UnknownResult // default validity
	if s.withValidation {
		validationStatus = secret.ValidationStatus
	}
	secret.Severity = getSeverity(s.twomsRulesToBeApplied[secret.RuleID].Severity, validationStatus)
	secret.CvssScore = getCvssScore(s.rulesBaseRiskScore[secret.RuleID], validationStatus)
}

func getValidityScore(baseRiskScore float64, validationStatus secrets.ValidationResult) float64 {
	switch validationStatus {
	case secrets.ValidResult:
		return math.Min(1, 4-baseRiskScore)
	case secrets.InvalidResult:
		return math.Max(-1, 1-baseRiskScore)
	}
	return 0.0
}

func GetBaseRiskScore(category ruledefine.RuleCategory, ruleType uint8) float64 {
	var categoryScore uint8
	var ok bool
	// default to the lowest score if category not found, should only happen on custom rules with undefined category
	if categoryScore, ok = CategoryScoreMap[category]; !ok {
		categoryScore = 1
	}
	return float64(categoryScore)*0.6 + float64(ruleType)*0.4
}

func getCvssScore(baseRiskScore float64, validationStatus secrets.ValidationResult) float64 {
	validityScore := getValidityScore(baseRiskScore, validationStatus)
	cvssScore := (baseRiskScore+validityScore-1)*3 + 1
	return math.Round(cvssScore*10) / 10
}

func getSeverity(severity ruledefine.Severity, validationStatus secrets.ValidationResult) string {
	// set severity to default if empty, which can happen for custom regex
	if severity == "" {
		severity = ruledefine.High // default severity
	}

	severityIndex := slices.Index(ruledefine.SeverityOrder, severity)

	switch validationStatus {
	case secrets.ValidResult:
		// severity raises
		if severityIndex > 0 {
			severityIndex--
		}
	case secrets.InvalidResult:
		// severity lowers
		if severityIndex < len(ruledefine.SeverityOrder)-1 {
			severityIndex++
		}
	case secrets.UnknownResult:
		// severity remains the same
	}

	return string(ruledefine.SeverityOrder[severityIndex])
}

func (s *scorer) GetKeywords() map[string]struct{} {
	return s.keywords
}

func (s *scorer) GetRulesToBeApplied() map[string]config.Rule {
	return s.gitleaksRulesToBeApplied
}

func (s *scorer) GetRulesBaseRiskScore(ruleId string) float64 {
	return s.rulesBaseRiskScore[ruleId]
}
