package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"secureshift/internal/mode"
)

type User struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}

type pingReq struct {
	Target string `json:"target"`
}

type pingResp struct {
	Output string `json:"output,omitempty"`
	Error  string `json:"error,omitempty"`
}

// GetUserFromRequest - request'ten user bilgilerini çıkarır
func GetUserFromRequest(r *http.Request) (*User, error) {
	// Hem secure hem insecure modda ParseJWT kullan
	// ParseJWT fonksiyonu zaten mode kontrolü yapıyor olmalı
	claims, err := ParseJWT(r)
	if err != nil {
		return nil, err
	}

	username := fmt.Sprint(claims["username"])
	role := fmt.Sprint(claims["role"])

	return &User{
		Username: username,
		Role:     role,
	}, nil
}

// allowHostRegex: basit domain/IP whitelist'i (secure mod için)
var allowHostRegex = regexp.MustCompile(`^[A-Za-z0-9\.\-]{1,253}$`)
var ipv4Regex = regexp.MustCompile(`^(?:\d{1,3}\.){3}\d{1,3}$`)

func AdminPing(w http.ResponseWriter, r *http.Request) {
	// Admin kontrolü frontend'de yapılıyor, backend'de ek kontrol gerekmiyor

	// JSON ya da form verisi oku
	var req pingReq
	if strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, pingResp{Error: "Geçersiz istek gövdesi"})
			return
		}
	} else {
		if err := r.ParseForm(); err != nil {
			writeJSON(w, http.StatusBadRequest, pingResp{Error: "Form ayrıştırılamadı"})
			return
		}
		req.Target = r.FormValue("target")
	}

	target := strings.TrimSpace(req.Target)
	if target == "" {
		writeJSON(w, http.StatusBadRequest, pingResp{Error: "Target boş olamaz"})
		return
	}

	// Komut zaman aşımı (her iki mod için)
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// INSECURE: shell üzerinden çalıştır → injection'a açık (bilinçli)
	if !mode.IsSecure() {
		// DİKKAT: Bu satır bilerek güvensiz; kullanıcı girdisi shell'e direkt ekleniyor.
		cmdline := "ping -c 2 " + target
		cmd := exec.CommandContext(ctx, "sh", "-c", cmdline)

		var out bytes.Buffer
		var er bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &er

		if err := cmd.Run(); err != nil {
			writeJSON(w, http.StatusBadRequest, pingResp{Error: strings.TrimSpace(er.String())})
			return
		}
		writeJSON(w, http.StatusOK, pingResp{Output: out.String()})
		return
	}

	// SECURE: sadece domain/IP kabul et, shell kullanma → injection kapalı
	if !(allowHostRegex.MatchString(target) || ipv4Regex.MatchString(target)) {
		writeJSON(w, http.StatusBadRequest, pingResp{Error: "Geçersiz hedef formati"})
		return
	}

	// Argümanları ayrı ver (shell yok)
	cmd := exec.CommandContext(ctx, "ping", "-c", "2", target)

	var out bytes.Buffer
	var er bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &er

	if err := cmd.Run(); err != nil {
		// stderr'i kullanıcıya dönerken sadeleştir
		msg := strings.TrimSpace(er.String())
		if msg == "" {
			msg = "Komut başarısız"
		}
		writeJSON(w, http.StatusBadRequest, pingResp{Error: msg})
		return
	}
	writeJSON(w, http.StatusOK, pingResp{Output: out.String()})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
