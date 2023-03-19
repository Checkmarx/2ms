package plugins

type Plugin struct {
	Name string
	// TODO missing ID field
	URL   string // TODO remove as this is confluence coupled
	Email string // TODO remove as this is confluence coupled
	Token string // TODO remove as this is confluence coupled
}

type Plugins struct {
	plugins map[string]Plugin
}

type Content struct {
	Content     string
	Source      string
	OriginalUrl string // TODO remove as this is confluence coupled
}

func NewPlugins() *Plugins {
	plugins := make(map[string]Plugin)
	return &Plugins{plugins: plugins}
}

func (P *Plugins) AddPlugin(name string, url string, email string, token string) {
	P.plugins["Name"] = Plugin{
		Name: name,
		URL:  url, Email: email,
		Token: token,
	}
}

func (P *Plugins) RunPlugins() ([]Content, error) {
	contents := []Content{}
	for _, p := range P.plugins {
		switch p.Name {
		case "confluence":
			plugin, err := p.RunPlugin()
			if err != nil {
				return nil, err
			}
			contents = append(contents, plugin...)
		default:
		}
	}
	return contents, nil
}
