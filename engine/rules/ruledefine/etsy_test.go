package ruledefine

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEtsyAccessToken(t *testing.T) {
	tests := []struct {
		name           string
		truePositives  []string
		falsePositives []string
	}{
		{
			name: "EtsyAccessToken validation",
			truePositives: []string{
				"string ETSYToken = \"6bqz6k10647mi23g8xgui188\";",
				"ETSYToken := \"6bqz6k10647mi23g8xgui188\"",
				"ETSY_TOKEN ::= \"6bqz6k10647mi23g8xgui188\"",
				"ETSY_TOKEN ?= \"6bqz6k10647mi23g8xgui188\"",
				"ETSYToken=\"6bqz6k10647mi23g8xgui188\"",
				"{\n    \"ETSY_token\": \"6bqz6k10647mi23g8xgui188\"\n}",
				"{\"config.ini\": \"ETSY_TOKEN=6bqz6k10647mi23g8xgui188\\nBACKUP_ENABLED=true\"}",
				"ETSY_token: '6bqz6k10647mi23g8xgui188'",
				"var ETSYToken string = \"6bqz6k10647mi23g8xgui188\"",
				"ETSYToken := `6bqz6k10647mi23g8xgui188`",
				"ETSYToken = \"6bqz6k10647mi23g8xgui188\"",
				"  \"ETSYToken\" => \"6bqz6k10647mi23g8xgui188\"",
				"ETSYToken = \"6bqz6k10647mi23g8xgui188\"",
				"<ETSYToken>\n    6bqz6k10647mi23g8xgui188\n</ETSYToken>",
				"ETSY_token: \"6bqz6k10647mi23g8xgui188\"",
				"String ETSYToken = \"6bqz6k10647mi23g8xgui188\";",
				"$ETSYToken .= \"6bqz6k10647mi23g8xgui188\"",
				"ETSYToken = '6bqz6k10647mi23g8xgui188'",
				"System.setProperty(\"ETSY_TOKEN\", \"6bqz6k10647mi23g8xgui188\")",
				"ETSY_TOKEN := \"6bqz6k10647mi23g8xgui188\"",
				"ETSYToken=6bqz6k10647mi23g8xgui188",
				"ETSYToken = 6bqz6k10647mi23g8xgui188",
				"ETSY_token: 6bqz6k10647mi23g8xgui188",
				"var ETSYToken = \"6bqz6k10647mi23g8xgui188\"",
				"ETSY_TOKEN = \"6bqz6k10647mi23g8xgui188\"",
				"ETSY_TOKEN :::= \"6bqz6k10647mi23g8xgui188\"",
				"etsyToken = \"6bqz6k10647mi23g8xgui188\"",
				"{\"config.ini\": \"ETSY_TOKEN=6bqz6k10647mi23g8xgui188\\nBACKUP_ENABLED=true\"}",
				"etsy_token: '6bqz6k10647mi23g8xgui188'",
				"String etsyToken = \"6bqz6k10647mi23g8xgui188\";",
				"etsyToken = \"6bqz6k10647mi23g8xgui188\"",
				"System.setProperty(\"ETSY_TOKEN\", \"6bqz6k10647mi23g8xgui188\")",
				"etsy_token: 6bqz6k10647mi23g8xgui188",
				"etsy_token: \"6bqz6k10647mi23g8xgui188\"",
				"var etsyToken = \"6bqz6k10647mi23g8xgui188\"",
				"$etsyToken .= \"6bqz6k10647mi23g8xgui188\"",
				"etsy_TOKEN = \"6bqz6k10647mi23g8xgui188\"",
				"etsy_TOKEN ::= \"6bqz6k10647mi23g8xgui188\"",
				"<etsyToken>\n    6bqz6k10647mi23g8xgui188\n</etsyToken>",
				"string etsyToken = \"6bqz6k10647mi23g8xgui188\";",
				"var etsyToken string = \"6bqz6k10647mi23g8xgui188\"",
				"etsyToken = '6bqz6k10647mi23g8xgui188'",
				"  \"etsyToken\" => \"6bqz6k10647mi23g8xgui188\"",
				"etsy_TOKEN := \"6bqz6k10647mi23g8xgui188\"",
				"etsy_TOKEN :::= \"6bqz6k10647mi23g8xgui188\"",
				"etsy_TOKEN ?= \"6bqz6k10647mi23g8xgui188\"",
				"etsyToken=\"6bqz6k10647mi23g8xgui188\"",
				"etsyToken=6bqz6k10647mi23g8xgui188",
				"etsyToken = 6bqz6k10647mi23g8xgui188",
				"{\n    \"etsy_token\": \"6bqz6k10647mi23g8xgui188\"\n}",
				"etsyToken := \"6bqz6k10647mi23g8xgui188\"",
				"etsyToken := `6bqz6k10647mi23g8xgui188`",
				"var EtsyToken = \"6bqz6k10647mi23g8xgui188\"",
				"EtsyToken = '6bqz6k10647mi23g8xgui188'",
				"Etsy_TOKEN ::= \"6bqz6k10647mi23g8xgui188\"",
				"EtsyToken=\"6bqz6k10647mi23g8xgui188\"",
				"EtsyToken = 6bqz6k10647mi23g8xgui188",
				"<EtsyToken>\n    6bqz6k10647mi23g8xgui188\n</EtsyToken>",
				"Etsy_token: 6bqz6k10647mi23g8xgui188",
				"Etsy_token: \"6bqz6k10647mi23g8xgui188\"",
				"var EtsyToken string = \"6bqz6k10647mi23g8xgui188\"",
				"EtsyToken := \"6bqz6k10647mi23g8xgui188\"",
				"Etsy_TOKEN = \"6bqz6k10647mi23g8xgui188\"",
				"String EtsyToken = \"6bqz6k10647mi23g8xgui188\";",
				"$EtsyToken .= \"6bqz6k10647mi23g8xgui188\"",
				"EtsyToken = \"6bqz6k10647mi23g8xgui188\"",
				"Etsy_TOKEN ?= \"6bqz6k10647mi23g8xgui188\"",
				"EtsyToken = \"6bqz6k10647mi23g8xgui188\"",
				"EtsyToken=6bqz6k10647mi23g8xgui188",
				"string EtsyToken = \"6bqz6k10647mi23g8xgui188\";",
				"EtsyToken := `6bqz6k10647mi23g8xgui188`",
				"System.setProperty(\"ETSY_TOKEN\", \"6bqz6k10647mi23g8xgui188\")",
				"  \"EtsyToken\" => \"6bqz6k10647mi23g8xgui188\"",
				"Etsy_TOKEN := \"6bqz6k10647mi23g8xgui188\"",
				"Etsy_TOKEN :::= \"6bqz6k10647mi23g8xgui188\"",
				"{\n    \"Etsy_token\": \"6bqz6k10647mi23g8xgui188\"\n}",
				"{\"config.ini\": \"ETSY_TOKEN=6bqz6k10647mi23g8xgui188\\nBACKUP_ENABLED=true\"}",
				"Etsy_token: '6bqz6k10647mi23g8xgui188'",
			},
			falsePositives: []string{
				"SetSysctl = \"r54xtprrf2b7kvng4k255446\"",
				"\tif err := sysctl.SetSysctl(sysctlBridgeCallIPTables); err != nil {",
				"g6Rib2R5hqhkZXRhY2hlZMOpaGFzaF90eXBlCqNrZXnEIwEgETSYcPQGcaAxl8vuQDLahSfhxkEEHu2flbF9ErAooEoKp3BheWxvYWTFAwB7ImJvZHkiOnsia2V5Ijp7ImVsZGVzdF9raWQiOiIwMTIwMTEzNDk4NzBmNDA2NzFhMDMxOTdjYmVlNDAzMmRhODUyN2UxYzY0MTA0MWVlZDlmOTViMTdkMTJiMDI4YTA0YTBhIiwiaG9zdCI6ImtleWJhc2UuaW8iLCJraWQiOiIwMTIwMTEzNDk4NzBmNDA2NzFhMDMxOTdjYmVlNDAzMmRhODUyN2UxYzY0MTA0MWVlZDlmOTViMTdkMTJiMDI4YTA0YTBhIiwidWlkIjoiYzUyZjc2M2MxNzYyNWZiMTI5YWU1ZDZmZThhMGUzMTkiLCJ1c2VybmFtZSI6ImttYXJla3NwYXJ0eiJ9LCJzZXJ2aWNlIjp7Imhvc3RuYW1lIjoia3lsZS5tYXJlay1zcGFydHoub3JnIiwicHJvdG9jb2wiOiJodHRwOiJ9LCJ0eXBlIjoid2ViX3NlcnZpY2VfYmluZGluZyIsInZlcnNpb24iOjF9LCJjbGllbnQiOnsibmFtZSI6ImtleWJhc2UuaW8gZ28gY2xpZW50IiwidmVyc2lvbiI6IjEuMC4xNCJ9LCJjdGltZSI6MTQ1ODU5MDYyMSwiZXhwaXJlX2luIjo1MDQ1NzYwMDAsIm1lcmtsZV9yb290Ijp7ImN0aW1lIjoxNDU4NTkwNTgzLCJoYXNoIjoiODQ0ZWRkNGU0OTQ3MWUzNWQxZTFkOTM5YTc0ZjUwMDc5Nzg3NzljMTAwYzY1NGE2OGI1NDNhYzY2Y2NlYTQ1MGFjNTllNmY3Yjc4ZGZiN2MyYzdjMmYwMzJiYTA2MzdjMzVjZDk1ZGYyZmRiNjFlNjgxMjVmNDkxNjVlZDkwNzMiLCJzZXFubyI6NDE3Mjk5fSwicHJldiI6IjdmNWFkMGZlZmQxNjM4ZjBlOTc1MTk3NzA5YTk2OTVkZmQ1NzU0MTA4NTYxZGUzMDM0ODc2NDcxODdhMDkyYzUiLCJzZXFubyI6OSwidGFnIjoic2lnbmF0dXJlIn2jc2lnxEDDVCB/SdOzo+BznIUCCa5DgISbH+0noUjyAJ4r0sH/tj8lYNpHw3WR93SBCufeElsl7KrxVdg5qU5ADYj26wgOqHNpZ190eXBlIKN0YWfNAgKndmVyc2lvbgE=",
				"in XCBuild.XCBBuildServiceSession.setSystemInfo(operatingSystemVersion: __C.NSOperatingSystemVersion, productBuildVersion: Swift.String, nativeArchitecture: Swift.String, completion: (Swift.Bool) -> ()) -> ()",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := ConvertNewRuleToGitleaksRule(EtsyAccessToken())
			d := createSingleRuleDetector(rule)

			// validate true positives if any specified
			for _, truePositive := range tt.truePositives {
				findings := d.DetectString(truePositive)
				assert.GreaterOrEqual(t, len(findings), 1, fmt.Sprintf("failed to detect true positive: %s", truePositive))
			}

			// validate false positives if any specified
			for _, falsePositive := range tt.falsePositives {
				findings := d.DetectString(falsePositive)
				assert.Equal(t, 0, len(findings), fmt.Sprintf("unexpectedly found false positive: %s", falsePositive))
			}
		})
	}
}
