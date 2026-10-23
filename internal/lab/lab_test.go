package lab

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestTenantIsolationMatrix(t *testing.T) {
	for _, variant := range []string{"vulnerable", "patched"} {
		t.Run(variant, func(t *testing.T) {
			handler, err := New(variant)
			if err != nil {
				t.Fatal(err)
			}
			for _, who := range []string{"a", "b"} {
				for _, owner := range []string{"a", "b"} {
					req := httptest.NewRequest("GET", "/exports/export-"+owner, nil)
					req.Header.Set("Authorization", "Bearer lab-only-token-"+who)
					recorder := httptest.NewRecorder()
					handler.ServeHTTP(recorder, req)
					want := http.StatusOK
					if variant == "patched" && who != owner {
						want = http.StatusNotFound
					}
					if recorder.Code != want {
						t.Fatalf("%s -> %s: got %d want %d", who, owner, recorder.Code, want)
					}
					if want == http.StatusOK {
						var item Export
						if err := json.Unmarshal(recorder.Body.Bytes(), &item); err != nil {
							t.Fatal(err)
						}
						if item.ID != "export-"+owner || item.Tenant != "tenant-"+owner || !strings.Contains(item.Content, strings.ToUpper(owner)) {
							t.Fatalf("unexpected protected resource: %+v", item)
						}
					} else if strings.Contains(recorder.Body.String(), "SYNTHETIC") {
						t.Fatal("denial leaked protected content")
					}
				}
			}
		})
	}
}
func TestAuthenticationAndMissingObjects(t *testing.T) {
	for _, variant := range []string{"vulnerable", "patched"} {
		handler, _ := New(variant)
		for _, tc := range []struct {
			path, auth string
			status     int
		}{
			{"/exports/export-a", "", 401},
			{"/exports/export-a", "Bearer invalid", 401},
			{"/exports/export-a", "Basic lab-only-token-a", 401},
			{"/exports/export-a", "Bearer lab-only-token-a extra", 401},
			{"/exports/absent", "Bearer lab-only-token-a", 404},
			{"/exports/export-a", "bearer lab-only-token-a", 200},
		} {
			r := httptest.NewRequest("GET", tc.path, nil)
			r.Header.Set("Authorization", tc.auth)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("%s %s got %d", variant, tc.path, w.Code)
			}
		}
	}
}
func TestConcurrentIdentitiesRemainIsolated(t *testing.T) {
	handler, _ := New("patched")
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			who := "a"
			if i%2 == 1 {
				who = "b"
			}
			r := httptest.NewRequest("GET", "/exports", nil)
			r.Header.Set("Authorization", "Bearer lab-only-token-"+who)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			var exports []Export
			if err := json.Unmarshal(w.Body.Bytes(), &exports); err != nil {
				t.Error(err)
				return
			}
			if len(exports) != 1 || exports[0].Tenant != "tenant-"+who {
				t.Errorf("identity leak: %s %+v", who, exports)
			}
		}(i)
	}
	wg.Wait()
}
func TestMetadataResetAndVariant(t *testing.T) {
	if _, err := New("production"); err == nil {
		t.Fatal("unknown variant accepted")
	}
	for i := 0; i < 2; i++ {
		handler, _ := New("patched")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", "/metadata", nil))
		var data map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
			t.Fatal(err)
		}
		if data["variant"] != "patched" || len(data["fixture_sha256"]) != 64 {
			t.Fatal(data)
		}
		for _, method := range []string{"POST", "PUT", "DELETE"} {
			w = httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest(method, "/exports/export-a", nil))
			if w.Code != http.StatusMethodNotAllowed {
				t.Fatalf("%s unexpectedly accepted", method)
			}
		}
	}
}
