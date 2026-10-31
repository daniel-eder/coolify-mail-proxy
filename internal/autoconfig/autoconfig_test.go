package autoconfig

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/coolify-mail-proxy/mailproxy/internal/config"
)

func handler(t *testing.T) http.Handler {
	t.Helper()
	cfg, err := config.LoadFrom(func(k string) string {
		return map[string]string{
			"MAIL_DOMAINS": "a.com,b.com", "CERT_SOURCE": "selfsigned",
			"UPSTREAM_IMAP": "imap.p.test", "UPSTREAM_POP3": "pop.p.test", "UPSTREAM_SMTP": "smtp.p.test",
		}[k]
	})
	if err != nil {
		t.Fatal(err)
	}
	return (&Handler{Cfg: cfg, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}).Routes()
}

func do(h http.Handler, method, host, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Host = host
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestThunderbird(t *testing.T) {
	h := handler(t)
	w := do(h, "GET", "autoconfig.a.com", "/mail/config-v1.1.xml", "")
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	b := w.Body.String()
	for _, want := range []string{
		"<hostname>mail.a.com</hostname>",
		`<incomingServer type="imap">`, `<incomingServer type="pop3">`,
		"<port>993</port>", "<port>143</port>", "<port>995</port>", "<port>110</port>", "<port>465</port>", "<port>587</port>",
		"<socketType>SSL</socketType>", "<socketType>STARTTLS</socketType>",
	} {
		if !strings.Contains(b, want) {
			t.Errorf("missing %q in\n%s", want, b)
		}
	}
	if strings.Index(b, "<port>993</port>") > strings.Index(b, "<port>143</port>") {
		t.Error("implicit TLS should be listed first")
	}
	if strings.Contains(b, "p.test") {
		t.Error("upstream host must not leak")
	}
	if do(h, "GET", "autoconfig.evil.com", "/mail/config-v1.1.xml", "").Code != 404 {
		t.Error("unknown domain should 404")
	}
	if w := do(h, "GET", "example.org", "/.well-known/autoconfig/mail/config-v1.1.xml?emailaddress=x@b.com", ""); !strings.Contains(w.Body.String(), "mail.b.com") {
		t.Error("emailaddress fallback failed")
	}
}

func TestOutlook(t *testing.T) {
	h := handler(t)
	req := `<?xml version="1.0"?><Autodiscover><Request><EMailAddress>joe@b.com</EMailAddress></Request></Autodiscover>`
	w := do(h, "POST", "autodiscover.a.com", "/autodiscover/autodiscover.xml", req)
	b := w.Body.String()
	for _, want := range []string{"<Server>mail.b.com</Server>", "<LoginName>joe@b.com</LoginName>",
		"<Type>IMAP</Type>", "<Type>POP3</Type>", "<Type>SMTP</Type>", "<Port>993</Port>", "<Port>995</Port>", "<Port>465</Port>"} {
		if !strings.Contains(b, want) {
			t.Errorf("missing %q in\n%s", want, b)
		}
	}
	if strings.Contains(b, "<Port>143</Port>") {
		t.Error("outlook should only get the preferred endpoint")
	}
	if do(h, "POST", "autodiscover.x.com", "/autodiscover/autodiscover.xml", "<EMailAddress>a@x.com</EMailAddress>").Code != 404 {
		t.Error("unknown domain should 404")
	}
}
