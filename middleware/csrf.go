package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
)

// GenerateCSRFToken rastgele bir CSRF token üretir.
func GenerateCSRFToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// CSRF middleware'i state-changing (POST, PUT, DELETE vb.) isteklerde CSRF token doğrulaması yapar.
func CSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// API istekleri (X-API-Key ile) veya /form/submit rotaları CSRF'ten muaftır.
		// /form/submit rotaları için public bir submission olduğu için honeypot kullanılıyor.
		isAPI := strings.HasPrefix(r.URL.Path, "/api/") && r.Header.Get("X-API-Key") != ""
		isFormSubmit := strings.HasPrefix(r.URL.Path, "/form/submit/")
		
		if isAPI || isFormSubmit {
			next.ServeHTTP(w, r)
			return
		}

		if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete || r.Method == http.MethodPatch {
			// Sadece form gönderimlerinde veya header üzerinden token kontrolü yap.
			// CSRF token formdan alınır
			token := r.FormValue("csrf_token")
			if token == "" {
				token = r.Header.Get("X-CSRF-Token")
			}

			// CSRF token çerezden alınır
			cookie, err := r.Cookie("csrf_token")
			
			if err != nil || cookie.Value == "" || token == "" || token != cookie.Value {
				http.Error(w, "Geçersiz veya eksik CSRF token", http.StatusForbidden)
				return
			}
		} else if r.Method == http.MethodGet {
			// GET isteklerinde çerezde CSRF token yoksa oluştur.
			_, err := r.Cookie("csrf_token")
			if err != nil {
				newToken := GenerateCSRFToken()
				http.SetCookie(w, &http.Cookie{
					Name:     "csrf_token",
					Value:    newToken,
					Path:     "/",
					HttpOnly: false, // JS (Alpine vb.) okuyabilsin diye false
					SameSite: http.SameSiteLaxMode,
					Secure:   false, // Canlıda true yapılmalı
				})
			}
		}

		next.ServeHTTP(w, r)
	})
}
