module github.com/checkmarx/2ms/v4

go 1.24.4

replace (
	// Replace all oauth2 versions with safe v0.30.0 to fix vulnerabilities
	golang.org/x/oauth2 => golang.org/x/oauth2 v0.30.0
	golang.org/x/oauth2 v0.0.0-20190226205417-e64efc72b421 => golang.org/x/oauth2 v0.30.0
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45 => golang.org/x/oauth2 v0.30.0
	golang.org/x/oauth2 v0.0.0-20191202225959-858c2ad4c8b6 => golang.org/x/oauth2 v0.30.0
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d => golang.org/x/oauth2 v0.30.0
	golang.org/x/oauth2 v0.0.0-20200902213428-5d25da1a8d43 => golang.org/x/oauth2 v0.30.0
	golang.org/x/oauth2 v0.0.0-20201109201403-9fd604954f58 => golang.org/x/oauth2 v0.30.0
	golang.org/x/oauth2 v0.0.0-20201208152858-08078c50e5b5 => golang.org/x/oauth2 v0.30.0
	golang.org/x/oauth2 v0.0.0-20210218202405-ba52d332ba99 => golang.org/x/oauth2 v0.30.0
	golang.org/x/oauth2 v0.0.0-20210220000619-9bb904979d93 => golang.org/x/oauth2 v0.30.0
	golang.org/x/oauth2 v0.0.0-20210313182246-cd4f82c27b84 => golang.org/x/oauth2 v0.30.0
	golang.org/x/oauth2 v0.0.0-20210514164344-f6687ab2804c => golang.org/x/oauth2 v0.30.0
	golang.org/x/oauth2 v0.0.0-20210628180205-a41e5a781914 => golang.org/x/oauth2 v0.30.0
	golang.org/x/oauth2 v0.0.0-20210805134026-6f1e6394065a => golang.org/x/oauth2 v0.30.0
	golang.org/x/oauth2 v0.0.0-20210819190943-2bc19b11175f => golang.org/x/oauth2 v0.30.0
	golang.org/x/oauth2 v0.0.0-20211104180415-d3ed0bb246c8 => golang.org/x/oauth2 v0.30.0
	golang.org/x/oauth2 v0.0.0-20220223155221-ee480838109b => golang.org/x/oauth2 v0.30.0
	golang.org/x/oauth2 v0.0.0-20220309155454-6242fa91716a => golang.org/x/oauth2 v0.30.0
	golang.org/x/oauth2 v0.0.0-20220411215720-9780585627b5 => golang.org/x/oauth2 v0.30.0
	golang.org/x/oauth2 v0.0.0-20220608161450-d0670ef3b1eb => golang.org/x/oauth2 v0.30.0
	golang.org/x/oauth2 v0.0.0-20220622183110-fd043fe589d2 => golang.org/x/oauth2 v0.30.0
	golang.org/x/oauth2 v0.0.0-20220822191816-0ebed06d0094 => golang.org/x/oauth2 v0.30.0
	golang.org/x/oauth2 v0.0.0-20220909003341-f21342109be1 => golang.org/x/oauth2 v0.30.0
	golang.org/x/oauth2 v0.0.0-20221006150949-b44042a4b9c1 => golang.org/x/oauth2 v0.30.0
	golang.org/x/oauth2 v0.0.0-20221014153046-6fdb5e3db783 => golang.org/x/oauth2 v0.30.0
	golang.org/x/oauth2 v0.26.0 => golang.org/x/oauth2 v0.30.0
	golang.org/x/oauth2 v0.4.0 => golang.org/x/oauth2 v0.30.0
	golang.org/x/oauth2 v0.5.0 => golang.org/x/oauth2 v0.30.0
	golang.org/x/oauth2 v0.6.0 => golang.org/x/oauth2 v0.30.0
	golang.org/x/oauth2 v0.7.0 => golang.org/x/oauth2 v0.30.0
	golang.org/x/oauth2 v0.8.0 => golang.org/x/oauth2 v0.30.0

	google.golang.org/grpc => google.golang.org/grpc v1.72.2
)

require (
	github.com/bwmarrin/discordgo v0.27.1
	github.com/gitleaks/go-gitdiff v0.9.1
	github.com/h2non/filetype v1.1.3
	github.com/rs/zerolog v1.33.0
	github.com/shirou/gopsutil v3.21.11+incompatible
	github.com/slack-go/slack v0.12.2
	github.com/spf13/cobra v1.9.1
	github.com/spf13/pflag v1.0.6
	github.com/spf13/viper v1.20.1
	github.com/stretchr/testify v1.10.0
	github.com/zricethezav/gitleaks/v8 v8.28.0
	go.uber.org/mock v0.5.2
	golang.org/x/net v0.40.0
	golang.org/x/sync v0.14.0
	golang.org/x/time v0.5.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	dario.cat/mergo v1.0.1 // indirect
	github.com/BobuSumisu/aho-corasick v1.0.3 // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver/v3 v3.3.0 // indirect
	github.com/Masterminds/sprig/v3 v3.3.0 // indirect
	github.com/STARRY-S/zip v0.2.1 // indirect
	github.com/andybalholm/brotli v1.1.2-0.20250424173009-453214e765f3 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/bodgit/plumbing v1.3.0 // indirect
	github.com/bodgit/sevenzip v1.6.0 // indirect
	github.com/bodgit/windows v1.0.1 // indirect
	github.com/charmbracelet/lipgloss v0.7.1 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dsnet/compress v0.0.2-0.20230904184137-39efe44ab707 // indirect
	github.com/fatih/semgroup v1.2.0 // indirect
	github.com/fsnotify/fsnotify v1.8.0 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-viper/mapstructure/v2 v2.3.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/huandu/xstrings v1.5.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/compress v1.17.11 // indirect
	github.com/klauspost/pgzip v1.2.6 // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/lucasjones/reggen v0.0.0-20200904144131-37ba4fa293bb // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.14 // indirect
	github.com/mholt/archives v0.1.3 // indirect
	github.com/mikelolasagasti/xz v1.0.1 // indirect
	github.com/minio/minlz v1.0.0 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/muesli/reflow v0.3.0 // indirect
	github.com/muesli/termenv v0.15.1 // indirect
	github.com/nwaples/rardecode/v2 v2.1.0 // indirect
	github.com/pelletier/go-toml/v2 v2.2.3 // indirect
	github.com/pierrec/lz4/v4 v4.1.21 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/rivo/uniseg v0.4.4 // indirect
	github.com/sagikazarmark/locafero v0.9.0 // indirect
	github.com/shopspring/decimal v1.4.0 // indirect
	github.com/sorairolake/lzip-go v0.3.5 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/afero v1.14.0 // indirect
	github.com/spf13/cast v1.7.1 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/tetratelabs/wazero v1.9.0 // indirect
	github.com/ulikunitz/xz v0.5.12 // indirect
	github.com/wasilibs/go-re2 v1.9.0 // indirect
	github.com/wasilibs/wazero-helpers v0.0.0-20240620070341-3dff1577cd52 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go4.org v0.0.0-20230225012048-214862532bf5 // indirect
	golang.org/x/crypto v0.38.0 // indirect
	golang.org/x/exp v0.0.0-20250218142911-aa4b98e5adaa // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.25.0 // indirect
)
