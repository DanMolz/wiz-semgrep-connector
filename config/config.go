package config

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	MODE               string
	WIZ_API_ENDPOINT   string
	WIZ_CLIENT_ID      string
	WIZ_CLIENT_SECRET  string
	SEMGREP_API_URL    string
	SEMGREP_API_TOKEN  string
	SEMGREP_DEPLOYMENT string
	FETCH_INTERVAL     int
}

func LoadConfig() Config {
	loadEnv()

	return Config{
		MODE:               getEnv("MODE", "agent"),
		WIZ_API_ENDPOINT:   getEnv("WIZ_API_ENDPOINT", ""),
		WIZ_CLIENT_ID:      getEnv("WIZ_CLIENT_ID", ""),
		WIZ_CLIENT_SECRET:  getEnv("WIZ_CLIENT_SECRET", ""),
		SEMGREP_API_TOKEN:  getEnv("SEMGREP_API_TOKEN", ""),
		SEMGREP_API_URL:    getEnv("SEMGREP_API_URL", ""),
		SEMGREP_DEPLOYMENT: getEnv("SEMGREP_DEPLOYMENT", ""),
		FETCH_INTERVAL:     getEnvAsInt("FETCH_INTERVAL", 24),
	}
}

func loadEnv() {
	err := godotenv.Load()
	if err != nil && !os.IsNotExist(err) {
		log.Fatalf("Error loading .env file: %v", err)
	}
}

func getEnv(key string, defaultValue string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		return defaultValue
	}
	return value
}

func getEnvAsInt(name string, defaultValue int) int {
	valueStr := getEnv(name, "")
	if value, err := strconv.Atoi(valueStr); err == nil {
		return value
	}
	return defaultValue
}
