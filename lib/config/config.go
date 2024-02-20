package config

type Config struct {
	Name    string
	Version string
}

func LoadConfig(name string, version string) *Config {
	return &Config{Name: name, Version: version}
}
