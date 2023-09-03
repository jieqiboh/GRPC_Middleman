package constants

import (
	"strings"
)

func ToConstant(s string) string {
	return strings.ToUpper(strings.ReplaceAll(s, " ", "_"))
}

const (
	APIGATEWAY_URL = "http://localhost:8888/PSI"
)
