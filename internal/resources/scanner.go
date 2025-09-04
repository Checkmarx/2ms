package resources

type ScanConfig struct {
	IgnoreResultIds []string
	IgnoreRules     []string
	WithValidation  bool
	PluginName      string
}
