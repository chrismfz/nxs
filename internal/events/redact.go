package events

import (
	"regexp"
	"strings"
)

var credentialKeys = []string{
	"password", "passwd", "token", "secret", "apikey", "api_key",
	"authorization", "bearer", "access_token", "refresh_token",
	"db_password", "mysql_pwd", "aws_secret_access_key",
}

var urlRe = regexp.MustCompile(`(?i)https?://`)

func RedactFinding(f *Finding) {
	if f.Evidence != nil {
		for k := range f.Evidence {
			kl := strings.ToLower(k)
			for _, ck := range credentialKeys {
				if strings.Contains(kl, ck) {
					f.Evidence[k] = "[REDACTED]"
					break
				}
			}
		}
	}
	f.Message = defangURLs(f.Message)
	for i := range f.Samples {
		f.Samples[i].Content = defangURLs(f.Samples[i].Content)
	}
}

func defangURLs(s string) string {
	s = strings.ReplaceAll(s, "http://", "hxxp://")
	s = strings.ReplaceAll(s, "https://", "hxxps://")
	_ = urlRe
	return s
}
