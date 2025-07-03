package score

import (
	"math"

	"github.com/checkmarx/2ms/v3/engine/rules"
	"github.com/checkmarx/2ms/v3/lib/secrets"
)

func getCategoryScore(category rules.RuleCategory) uint8 {
	CategoryScore := map[rules.RuleCategory]uint8{
		rules.CategoryAuthenticationAndAuthorization: 4,
		rules.CategoryCryptocurrencyExchange:         4,
		rules.CategoryFinancialServices:              4,
		rules.CategoryPaymentProcessing:              4,
		rules.CategorySecurity:                       4,
		rules.CategoryAPIAccess:                      3,
		rules.CategoryCICD:                           3,
		rules.CategoryCloudPlatform:                  3,
		rules.CategoryDatabaseAsAService:             3,
		rules.CategoryDevelopmentPlatform:            3,
		rules.CategoryEmailDeliveryService:           3,
		rules.CategoryGeneralOrUnknown:               3,
		rules.CategoryInfrastructureAsCode:           3,
		rules.CategoryPackageManagement:              3,
		rules.CategorySourceCodeManagement:           3,
		rules.CategoryWebHostingAndDeployment:        3,
		rules.CategoryBackgroundProcessingService:    2,
		rules.CategoryCDN:                            2,
		rules.CategoryContentManagementSystem:        2,
		rules.CategoryCustomerSupport:                2,
		rules.CategoryDataAnalytics:                  2,
		rules.CategoryFileStorageAndSharing:          2,
		rules.CategoryIoTPlatform:                    2,
		rules.CategoryMappingAndLocationServices:     2,
		rules.CategoryNetworking:                     2,
		rules.CategoryPhotoSharing:                   2,
		rules.CategorySaaS:                           2,
		rules.CategoryShipping:                       2,
		rules.CategorySoftwareDevelopment:            2,
		rules.CategoryAIAndMachineLearning:           1,
		rules.CategoryApplicationMonitoring:          1,
		rules.CategoryECommercePlatform:              1,
		rules.CategoryMarketingAutomation:            1,
		rules.CategoryNewsAndMedia:                   1,
		rules.CategoryOnlineSurveyPlatform:           1,
		rules.CategoryProjectManagement:              1,
		rules.CategorySearchService:                  1,
		rules.CategorySocialMedia:                    1,
	}
	return CategoryScore[category]
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

func GetBaseRiskScore(category rules.RuleCategory, ruleType uint8) float64 {
	categoryScore := getCategoryScore(category)
	return float64(categoryScore)*0.6 + float64(ruleType)*0.4
}

func GetCvssScore(baseRiskScore float64, validationStatus secrets.ValidationResult) float64 {
	validityScore := getValidityScore(baseRiskScore, validationStatus)
	cvssScore := (baseRiskScore+validityScore-1)*3 + 1
	return math.Round(cvssScore*10) / 10
}
