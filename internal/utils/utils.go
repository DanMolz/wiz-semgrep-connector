package utils

import "strings"

// CapitalizeFirstChar capitalizes the first character of a string
func CapitalizeFirstChar(s string) string {
	if len(s) == 0 {
		return s
	}
	return strings.ToUpper(string(s[0])) + s[1:]
}
