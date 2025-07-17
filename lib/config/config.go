package config

type Config struct {
	Name    string
	Version string
}

func LoadConfig(name, version string) *Config {
	return &Config{Name: name, Version: version}
}
