package cmd

import (
	"flag"
	"fmt"
)

type ignoreOnExit string

const (
	ignoreOnExitNone    ignoreOnExit = "none"
	ignoreOnExitAll     ignoreOnExit = "all"
	ignoreOnExitResults ignoreOnExit = "results"
	ignoreOnExitErrors  ignoreOnExit = "errors"
)

// verify that ignoreOnExit implements flag.Value interface
// https://github.com/uber-go/guide/blob/master/style.md#verify-interface-compliance
var _ flag.Value = (*ignoreOnExit)(nil)

func (i *ignoreOnExit) String() string {
	return string(*i)
}

func (i *ignoreOnExit) Set(value string) error {
	switch value {
	case "none", "all", "results", "errors":
		*i = ignoreOnExit(value)
		return nil
	default:
		return fmt.Errorf("invalid value %s", value)
	}
}

func (i *ignoreOnExit) Type() string {
	return "ignoreOnExit"
}
