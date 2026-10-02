package gateway

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ngthdong/egressa/internal/telemetry"
)

func httptestScrape(t *testing.T, reg *telemetry.Registry) string {
	t.Helper()
	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	return rec.Body.String()
}

func containsLine(body, line string) bool {
	for _, l := range strings.Split(body, "\n") {
		if l == line {
			return true
		}
	}
	return false
}
