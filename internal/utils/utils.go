package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// CapitalizeFirstChar capitalizes the first character of a string
func CapitalizeFirstChar(s string) string {
	if len(s) == 0 {
		return s
	}
	return strings.ToUpper(string(s[0])) + s[1:]
}

func WriteToFile(input interface{}, filePath string) error {
	data, err := json.MarshalIndent(input, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling data: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("writing file: %w", err)
	}

	return nil
}
