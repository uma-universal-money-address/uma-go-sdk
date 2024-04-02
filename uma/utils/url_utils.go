package utils

import "strings"

func IsDomainLocalhost(domain string) bool {
	domainWithoutPort := strings.Split(domain, ":")[0]
	domainParts := strings.Split(domainWithoutPort, ".")
	tld := domainParts[len(domainParts)-1]
	return domainWithoutPort == "localhost" || domainWithoutPort == "127.0.0.1" || tld == "local" || tld == "internal"
}
