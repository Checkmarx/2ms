package wrapper

import (
	"testing"
)

func TestLoadAllRules(t *testing.T) {
	rules, _ := loadAllRules()

	if len(rules) != 147 {
		t.Errorf("not all rules were loaded, there should be %d", 147)
	}
}

func TestIsAllFilter_AllFilterNotPresent(t *testing.T) {
	filters := []string{"token", "key"}

	isAllFilter := isAllFilter(filters)

	if isAllFilter {
		t.Errorf("all rules were not selected")
	}
}

func TestIsAllFilter_AllFilterPresent(t *testing.T) {
	filters := []string{"token", "key", "all"}

	isAllFilter := isAllFilter(filters)

	if !isAllFilter {
		t.Errorf("all filter selected")
	}
}

func TestIsAllFilter_OnlyAll(t *testing.T) {
	filters := []string{"all"}

	isAllFilter := isAllFilter(filters)

	if !isAllFilter {
		t.Errorf("all filter selected")
	}
}

func TestGetRules_AllFilter(t *testing.T) {
	rules, _ := loadAllRules()
	filters := []string{"all"}

	filteredRules := getRulesToBeApplied(rules, filters)

	if len(filteredRules) != 147 {
		t.Errorf("not all rules were loaded, there should be %d", 147)
	}
}

func TestGetRules_TokenFilter(t *testing.T) {
	rules, _ := loadAllRules()
	filters := []string{"token"}

	filteredRules := getRulesToBeApplied(rules, filters)

	if len(filteredRules) != 87 {
		t.Errorf("not all rules were loaded, there should be %d", 87)
	}
}

func TestGetRules_KeyFilter(t *testing.T) {
	rules, _ := loadAllRules()
	filters := []string{"key"}

	filteredRules := getRulesToBeApplied(rules, filters)

	if len(filteredRules) != 31 {
		t.Errorf("not all rules were loaded, there should be %d", 31)
	}
}

func TestGetRules_IdFilter(t *testing.T) {
	rules, _ := loadAllRules()
	filters := []string{"id"}

	filteredRules := getRulesToBeApplied(rules, filters)

	if len(filteredRules) != 18 {
		t.Errorf("not all rules were loaded, there should be %d", 18)
	}
}

func TestGetRules_IdAndKeyFilters(t *testing.T) {
	rules, _ := loadAllRules()
	filters := []string{"id", "key"}

	filteredRules := getRulesToBeApplied(rules, filters)

	if len(filteredRules) != 46 {
		t.Errorf("not all rules were loaded, there should be %d", 46)
	}
}
