package handlers

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"secureshift/internal/mode"

	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

// Faturalar uploads altında tutuluyor
const baseInvoiceDir = "./web/uploads"

// invoiceID için yalnızca rakamlar (secure modda buna zorlayacağız)
var digitsOnlyRe = regexp.MustCompile(`^\d+$`)

// /downloadFile?invoiceID=1
// Insecure mod:
//   - invoiceID rakamsa -> "invoice<id>.pdf" (IDOR AÇIK)
//   - rakam değilse -> ham değeri path'e ekler (PATH TRAVERSAL AÇIK)
//
// Secure mod:
//   - invoiceID rakam olmalı
//   - JWT'ten alınan username ile DB'den users.id çekilir
//   - SADECE users.id == invoiceID ise izin verilir (IDOR KAPALI)
//   - base dışına çıkılmaz, sadece .pdf
func DownloadInvoice(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("invoiceID")
	if id == "" {
		http.Error(w, "invoiceID parametresi eksik", http.StatusBadRequest)
		return
	}

	// ========== INSECURE ==========
	if !mode.IsSecure() {
		var target string
		if digitsOnlyRe.MatchString(id) {
			// insecure modda da DB’den user_id eşleşmesi kullan
			username := cscurrentUsername(r)
			if username != "" {
				userIDStr, err := fetchUserIDByUsername(username)
				if err == nil && userIDStr == id {
					target = filepath.Join(baseInvoiceDir, fmt.Sprintf("invoice%s.pdf", id))
					serveFile(w, r, target)
					return
				}
			}
			// ID eşleşmezse: IDOR açık kalmaya devam etsin
			target = filepath.Join(baseInvoiceDir, fmt.Sprintf("invoice%s.pdf", id))
		} else {
			target = filepath.Join(baseInvoiceDir, id) // Path Traversal açık
		}
		serveFile(w, r, target)
		return
	}

	// ========== SECURE ==========
	// 1) invoiceID rakam olmalı
	if !digitsOnlyRe.MatchString(id) {
		http.Error(w, "Geçersiz invoiceID", http.StatusForbidden)
		return
	}

	// 2) Kullanıcı adını JWT'ten al
	username := cscurrentUsername(r)
	if username == "" {
		http.Error(w, "Kimlik doğrulama gerekli", http.StatusUnauthorized)
		return
	}

	// 3) DB'den bu kullanıcının users.id değerini çek
	userIDStr, err := fetchUserIDByUsername(username)
	if err != nil {
		http.Error(w, "Kullanıcı doğrulama hatası", http.StatusForbidden)
		return
	}

	// 4) SADECE kendi id'sine eşit invoiceID'ye izin ver
	if userIDStr != id {
		http.Error(w, "Bu faturaya erişim yetkiniz yok", http.StatusForbidden)
		return
	}

	// 5) Dosya ismi ve güvenlik kontrolleri
	filename := fmt.Sprintf("invoice%s.pdf", id)
	cleanName := filepath.Clean(filename)
	if strings.Contains(cleanName, "/") || strings.Contains(cleanName, `\`) {
		http.Error(w, "Geçersiz dosya adı", http.StatusForbidden)
		return
	}
	full := filepath.Join(baseInvoiceDir, cleanName)

	// base dışına çıkmayı engelle
	isInside, err := isPathUnderBase(full, baseInvoiceDir)
	if err != nil || !isInside {
		http.Error(w, "Yetkisiz yol", http.StatusForbidden)
		return
	}
	// yalnız .pdf
	if strings.ToLower(filepath.Ext(full)) != ".pdf" {
		http.Error(w, "Sadece PDF indirilebilir", http.StatusForbidden)
		return
	}

	serveFile(w, r, full)
}

// ---------------- DB yardımcıları ----------------

func fetchUserIDByUsername(username string) (string, error) {
	db, err := openDB()
	if err != nil {
		return "", err
	}
	defer db.Close()

	var userID int64
	err = db.QueryRow(`SELECT id FROM users WHERE username = ? LIMIT 1`, username).Scan(&userID)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d", userID), nil
}

func openDB() (*sql.DB, error) {
	// DB yolu için env değişkeni veya birkaç default deneme
	if p := os.Getenv("SECURESHIFT_DB"); p != "" {
		return sql.Open("sqlite3", p)
	}
	paths := []string{
		"./secureshift.db",
		"./data/secureshift.db",
		"./db.sqlite",
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return sql.Open("sqlite3", p)
		}
	}
	// Son çare: default konum (oluşmayabilir)
	return sql.Open("sqlite3", "./secureshift.db")
}

// ---------------- Auth yardımcıları ----------------

// JWT içinden username çek (auth.go/ParseJWT ile aynı mantık)
// FONKSİYON ADI DÜZELTİLDİ: cscurrentUsername -> currentUsername
func cscurrentUsername(r *http.Request) string {
	claims, err := ParseJWT(r)
	if err != nil || claims == nil {
		return ""
	}
	if u, ok := claims["username"].(string); ok && u != "" {
		return u
	}
	if sub, ok := claims["sub"].(string); ok && sub != "" {
		return sub
	}
	return ""
}

// ---------------- Ortak yardımcılar ----------------

func serveFile(w http.ResponseWriter, r *http.Request, path string) {
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, "Dosya bulunamadı", http.StatusNotFound)
		return
	}
	defer f.Close()

	ct := mime.TypeByExtension(filepath.Ext(path))
	if ct == "" {
		buf := make([]byte, 512)
		n, _ := f.Read(buf)
		ct = http.DetectContentType(buf[:n])
		_, _ = f.Seek(0, 0)
	}
	w.Header().Set("Content-Type", ct)

	filename := filepath.Base(path)
	w.Header().Set("Content-Disposition", `inline; filename="`+filename+`"`)

	if _, err := io.Copy(w, f); err != nil {
		http.Error(w, "Dosya aktarım hatası", http.StatusInternalServerError)
		return
	}
}

func isPathUnderBase(path string, base string) (bool, error) {
	absTarget, err1 := filepath.Abs(path)
	absBase, err2 := filepath.Abs(base)
	if err1 != nil || err2 != nil {
		return false, errors.New("abs path error")
	}
	absTarget = filepath.Clean(absTarget)
	absBase = filepath.Clean(absBase)

	if absTarget == absBase {
		return true, nil
	}
	rel, err := filepath.Rel(absBase, absTarget)
	if err != nil {
		return false, err
	}
	return !strings.HasPrefix(rel, ".."), nil
}

// /api/invoices - Kullanıcının faturalarını listele
func ListUserInvoices(w http.ResponseWriter, r *http.Request) {
	// Kullanıcı adını JWT'ten al
	username := cscurrentUsername(r)
	if username == "" {
		http.Error(w, "Kimlik doğrulama gerekli", http.StatusUnauthorized)
		return
	}

	var invoiceIDs []string

	if mode.IsSecure() {
		// Secure modda: DB'den bu kullanıcının users.id değerini çek
		userIDStr, err := fetchUserIDByUsername(username)
		if err != nil {
			http.Error(w, "Kullanıcı doğrulama hatası", http.StatusForbidden)
			return
		}
		// Sadece kendi user ID'si
		invoiceIDs = []string{userIDStr}
	} else {
		// Insecure modda: eski mapping'i kullan
		invoiceMap := map[string][]string{
			"administrator": {"1"},
			"elliot":        {"2", "3"},
			"darlene":       {"3"},
			"ozcanpng":      {"4"},
		}
		if ids, exists := invoiceMap[username]; exists {
			invoiceIDs = ids
		}
	}

	// JSON response oluştur
	w.Header().Set("Content-Type", "application/json")

	if len(invoiceIDs) == 0 {
		fmt.Fprintf(w, `{"invoices": []}`)
		return
	}

	// Invoice listesi JSON'u oluştur
	var invoiceList []string
	for _, id := range invoiceIDs {
		invoiceList = append(invoiceList, `{"id": `+id+`, "title": "Fatura"}`)
	}

	fmt.Fprintf(w, `{"invoices": [%s]}`, strings.Join(invoiceList, ", "))
}
