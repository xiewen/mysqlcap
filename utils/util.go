package utils

import (
	"os"
	"strconv"
)

// GetEnvInt get integer env
func GetEnvInt(key string, fallback int) int {
	if value, ok := os.LookupEnv(key); ok {
		v, err := strconv.Atoi(value)
		if err != nil {
			return 0
		}
		return v
	}
	return fallback
}

// GetEnvStr get string env
func getEnvStr(key string, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
