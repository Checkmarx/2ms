package cmd

func IsNeedReturnErrorCodeFor(kind ignoreOnExit) bool {
	if ignoreOnExitVar == ignoreOnExitNone {
		return true
	}

	if ignoreOnExitVar == ignoreOnExitAll {
		return false
	}

	if ignoreOnExitVar != ignoreOnExit(kind) {
		return true
	}

	return false
}
