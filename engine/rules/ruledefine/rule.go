package ruledefine

import (
	"fmt"

	"regexp"
)

type RuleCategory string

const (
	CategoryAuthenticationAndAuthorization RuleCategory = "Authentication and Authorization"
	CategoryCryptocurrencyExchange         RuleCategory = "Cryptocurrency Exchange"
	CategoryFinancialServices              RuleCategory = "Financial Services"
	CategoryPaymentProcessing              RuleCategory = "Payment Processing"
	CategorySecurity                       RuleCategory = "Security"
	CategoryAPIAccess                      RuleCategory = "API Access"
	CategoryCICD                           RuleCategory = "CI/CD"
	CategoryCloudPlatform                  RuleCategory = "Cloud Platform"
	CategoryDatabaseAsAService             RuleCategory = "Database as a Service"
	CategoryDevelopmentPlatform            RuleCategory = "Development Platform"
	CategoryEmailDeliveryService           RuleCategory = "Email Delivery Service"
	CategoryInfrastructureAsCode           RuleCategory = "Infrastructure as Code (IaC)"
	CategoryPackageManagement              RuleCategory = "Package Management"
	CategorySourceCodeManagement           RuleCategory = "Source Code Management"
	CategoryWebHostingAndDeployment        RuleCategory = "Web Hosting and Deployment"
	CategoryBackgroundProcessingService    RuleCategory = "Background Processing Service"
	CategoryCDN                            RuleCategory = "CDN (Content Delivery Network)"
	CategoryContentManagementSystem        RuleCategory = "Content Management System (CMS)"
	CategoryCustomerSupport                RuleCategory = "Customer Support"
	CategoryDataAnalytics                  RuleCategory = "Data Analytics"
	CategoryFileStorageAndSharing          RuleCategory = "File Storage and Sharing"
	CategoryIoTPlatform                    RuleCategory = "IoT platform"
	CategoryMappingAndLocationServices     RuleCategory = "Mapping and Location Services"
	CategoryNetworking                     RuleCategory = "Networking"
	CategoryPhotoSharing                   RuleCategory = "Photo Sharing"
	CategorySaaS                           RuleCategory = "SaaS"
	CategoryShipping                       RuleCategory = "Shipping"
	CategorySoftwareDevelopment            RuleCategory = "Software Development"
	CategoryAIAndMachineLearning           RuleCategory = "AI and Machine Learning"
	CategoryApplicationMonitoring          RuleCategory = "Application Monitoring"
	CategoryECommercePlatform              RuleCategory = "E-commerce Platform"
	CategoryMarketingAutomation            RuleCategory = "Marketing Automation"
	CategoryNewsAndMedia                   RuleCategory = "News and Media"
	CategoryOnlineSurveyPlatform           RuleCategory = "Online Survey Platform"
	CategoryProjectManagement              RuleCategory = "Project Management"
	CategorySearchService                  RuleCategory = "Search Service"
	CategorySocialMedia                    RuleCategory = "Social Media"
	CategoryGeneralOrUnknown               RuleCategory = "General"
)

const TagApiKey = "api-key"
const TagClientId = "client-id"
const TagClientSecret = "client-secret"
const TagSecretKey = "secret-key"
const TagAccessKey = "access-key"
const TagAccessId = "access-id"
const TagApiToken = "api-token"
const TagAccessToken = "access-token"
const TagRefreshToken = "refresh-token"
const TagPrivateKey = "private-key"
const TagPublicKey = "public-key"
const TagEncryptionKey = "encryption-key"
const TagTriggerToken = "trigger-token"
const TagRegistrationToken = "registration-token"
const TagPassword = "password"
const TagUploadToken = "upload-token"
const TagPublicSecret = "public-secret"
const TagSensitiveUrl = "sensitive-url"
const TagWebhook = "webhook"

// define severity
type Severity string

const (
	Critical Severity = "Critical"
	High     Severity = "High"
	Medium   Severity = "Medium"
	Low      Severity = "Low"
	Info     Severity = "Info"
)

var SeverityOrder = []Severity{Critical, High, Medium, Low, Info}

type ScoreParameters struct {
	Category RuleCategory `json:"category"`
	RuleType uint8        `json:"ruleType"`
}

type Rule struct {
	BaseRuleID        string          `json:"baseRuleId"` // uuid4, should be consistent across changes in rule
	RuleID            string          `json:"ruleId"`
	Description       string          `json:"description"`
	Regex             string          `json:"regex"` // regex pattern as string
	Keywords          []string        `json:"keywords"`
	Entropy           float64         `json:"entropy"`
	Path              string          `json:"path"`        // present in some gitleaks secrets (regex)
	SecretGroup       int             `json:"secretGroup"` //nolint:lll // SecretGroup is used to extract secret from regex match and used as the group that will have its entropy checked if `entropy` is set.
	Severity          Severity        `json:"severity"`
	OldSeverity       string          `json:"oldSeverity"` // fallback for when critical is not enabled
	AllowLists        []*AllowList    `json:"allowLists"`
	Tags              []string        `json:"tags"`
	ScoreParameters   ScoreParameters `json:"scoreParameters"`   // used for ASPM
	DisableValidation bool            `json:"disableValidation"` // if true, validation checks will be skipped for this rule if any validation is possible
	Deprecated        bool            `json:"deprecated"`        // deprecated rules will remain in 2ms, with deprecated as true
	//Override bool 		// if true, this rule is allowed to override existing rules with the same RuleID/BaseRuleID
}

type AllowList struct { // For patterns that are allowed to be ignored
	Description    string   `json:"description"`
	MatchCondition string   `json:"matchCondition"` // determines whether all criteria must match. OR or AND
	Paths          []string `json:"paths"`          // regex
	RegexTarget    string   `json:"regexTarget"`    // match or line. Default match
	Regexes        []string `json:"regexes"`
	StopWords      []string `json:"stopWords"` // stop words that are allowed to be ignored
}

// CheckRequiredFields checks that required fields are present in the Rule.
// This is meant for user defined rules, default rules have more strict checks in unit tests
func (r Rule) CheckRequiredFields() []error {
	var errs []error
	if r.RuleID == "" || r.BaseRuleID == "" {
		errs = append(errs, fmt.Errorf("missing RuleID and/or BaseRuleID. Both are required"))
	}
	//Check for match with default rules
	//defaultRulesBaseIDs := getDefaultRulesBaseIDs()
	//defaultRuleIDs := getDefaultRulesIDs()
	//if

	switch {
	case r.Regex == "":
		errs = append(errs, fmt.Errorf("missing regex"))
	default:
		if _, err := regexp.Compile(r.Regex); err != nil {
			errs = append(errs, fmt.Errorf("invalid regex: %w", err))
		}
	}

	return nil
}

func (r Rule) AssignRuleIDIfEmpty() {
	if r.RuleID != "" {
		r.RuleID = r.BaseRuleID
	}
}
