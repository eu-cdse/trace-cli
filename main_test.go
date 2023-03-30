package main

import (
	"testing"
)

func TestValidateInputs(t *testing.T) {
	inputs_string := "abc:010203,def:040506"
	expected := []Input{
		Input{
			Name: "abc",
			Hash: "010203",
		},
		Input{
			Name: "def",
			Hash: "040506",
		},
	}
	actual := ValidateInputs(&inputs_string)
	expectArrayEqual(expected, *actual, t)
}

func TestValidateInputsEmpty(t *testing.T) {
	empty := ""
	expectArrayEqual([]Input{}, *ValidateInputs(&empty), t)
	expectEqual(nil, ValidateInputs(nil), t)
}
