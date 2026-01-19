package ruledefine

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

type Rule struct {
	RuleID            string       `json:"ruleId,omitempty" yaml:"ruleId,omitempty"` // uuid4, should be consistent across changes in rule
	RuleName          string       `json:"ruleName,omitempty" yaml:"ruleName,omitempty"`
	Description       string       `json:"description,omitempty" yaml:"description,omitempty"`
	Regex             string       `json:"regex,omitempty" yaml:"regex,omitempty"` // regex pattern as string
	Keywords          []string     `json:"keywords,omitempty" yaml:"keywords,omitempty"`
	Entropy           float64      `json:"entropy,omitempty" yaml:"entropy,omitempty"`
	Path              string       `json:"path,omitempty" yaml:"path,omitempty"`               // present in some gitleaks secrets (regex)
	SecretGroup       int          `json:"secretGroup,omitempty" yaml:"secretGroup,omitempty"` //nolint:lll // SecretGroup is used to extract secret from regex match and used as the group that will have its entropy checked if `entropy` is set.
	Severity          Severity     `json:"severity,omitempty" yaml:"severity,omitempty"`
	OldSeverity       string       `json:"oldSeverity,omitempty" yaml:"oldSeverity,omitempty"` //nolint:lll // fallback for when critical is not enabled, has no effect on open source
	AllowLists        []*AllowList `json:"allowLists,omitempty" yaml:"allowLists,omitempty"`
	Tags              []string     `json:"tags,omitempty" yaml:"tags,omitempty"`
	Category          RuleCategory `json:"category,omitempty" yaml:"category,omitempty"`                   // used for cvssScore
	ScoreRuleType     uint8        `json:"scoreRuleType,omitempty" yaml:"scoreRuleType,omitempty"`         // used for cvssScore
	DisableValidation bool         `json:"disableValidation,omitempty" yaml:"disableValidation,omitempty"` ////nolint:lll // if true, validation checks will be skipped for this rule if any validation is possible
	Deprecated        bool         `json:"deprecated,omitempty" yaml:"deprecated,omitempty"`
}

type AllowList struct { // For patterns that are allowed to be ignored
	Description    string   `json:"description,omitempty" yaml:"description,omitempty"`
	MatchCondition string   `json:"matchCondition,omitempty" yaml:"matchCondition,omitempty"` // determines whether all criteria must match. OR or AND
	Paths          []string `json:"paths,omitempty" yaml:"paths,omitempty"`                   // regex
	RegexTarget    string   `json:"regexTarget,omitempty" yaml:"regexTarget,omitempty"`       // match or line. Default match
	Regexes        []string `json:"regexes,omitempty" yaml:"regexes,omitempty"`
	StopWords      []string `json:"stopWords,omitempty" yaml:"stopWords,omitempty"` // stop words that are allowed to be ignored
}

func (r *Rule) CreateRuleNameFromRuleID() {
	r.RuleName = r.RuleID
}
