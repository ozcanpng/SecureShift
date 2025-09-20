package handlers

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"secureshift/internal/mode"
)

const (
	maxFileSize = 5 * 1024 * 1024 // 5MB limit for secure mode
	uploadDir   = "./web/uploads" // URL: http://localhost:3000/uploads/<name>
	logFile     = "./uploads.log"
)

// ========== UPLOAD HANDLER ==========
func FileUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Avatar mı güncellenecek? (opsiyonel)
	isAvatar := r.FormValue("use") == "avatar" || r.FormValue("avatar") == "1"

	// Parse form (limit only in secure mode)
	if mode.IsSecure() {
		_ = r.ParseMultipartForm(maxFileSize)
	} else {
		_ = r.ParseMultipartForm(100 << 20) // 100MB (intentionally lax)
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		logUploadAttempt("FAIL", "Dosya alınamadı: "+err.Error(), header)
		http.Error(w, "Dosya alınamadı", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Ensure upload dir exists
	_ = os.MkdirAll(uploadDir, 0755)

	if mode.IsSecure() {
		// ===== SECURE MODE =====
		logUploadAttempt("SECURE_START", "Güvenli mod ile upload", header)

		// 1) Boyut
		if header.Size > maxFileSize {
			logUploadAttempt("SECURE_BLOCK", fmt.Sprintf("Dosya çok büyük: %d bytes", header.Size), header)
			http.Error(w, fmt.Sprintf("Dosya çok büyük (max %dMB)", maxFileSize/(1024*1024)), http.StatusRequestEntityTooLarge)
			return
		}

		// 2) Uzantı (yalnızca jpg/jpeg/png)
		ext := strings.ToLower(filepath.Ext(header.Filename))
		allowedExts := []string{".jpg", ".jpeg", ".png"}
		if !contains(allowedExts, ext) {
			logUploadAttempt("SECURE_BLOCK", "Geçersiz uzantı: "+ext, header)
			http.Error(w, "Sadece JPG/JPEG/PNG dosyalarına izin verilir", http.StatusBadRequest)
			return
		}

		// 3) İçeriği oku
		content, err := io.ReadAll(file)
		if err != nil {
			logUploadAttempt("SECURE_ERROR", "Dosya okunamadı: "+err.Error(), header)
			http.Error(w, "Dosya okunamadı", http.StatusInternalServerError)
			return
		}

		// 4) MIME (gerçek içeriğe göre)
		mimeType := http.DetectContentType(content)
		allowedMimes := []string{"image/jpeg", "image/png"}
		if !containsMime(allowedMimes, mimeType) {
			logUploadAttempt("SECURE_BLOCK", "Geçersiz MIME: "+mimeType, header)
			http.Error(w, "Geçersiz dosya türü (MIME: "+mimeType+")", http.StatusBadRequest)
			return
		}

		// 5) Görsel decode edilebiliyor mu?
		if _, _, err := image.DecodeConfig(bytes.NewReader(content)); err != nil {
			logUploadAttempt("SECURE_BLOCK", "Geçersiz resim formatı: "+err.Error(), header)
			http.Error(w, "Geçersiz resim formatı", http.StatusBadRequest)
			return
		}

		// 6) Güvenli rastgele dosya adı
		randomBytes := make([]byte, 16)
		if _, err := rand.Read(randomBytes); err != nil {
			logUploadAttempt("SECURE_ERROR", "Random filename oluşturulamadı", header)
			http.Error(w, "Güvenlik hatası", http.StatusInternalServerError)
			return
		}
		secureFilename := hex.EncodeToString(randomBytes) + ext
		dstPath := filepath.Join(uploadDir, secureFilename)

		// 7) Yaz
		dst, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if err != nil {
			logUploadAttempt("SECURE_ERROR", "Dosya oluşturulamadı: "+err.Error(), header)
			http.Error(w, "Dosya kaydedilemedi", http.StatusInternalServerError)
			return
		}
		defer dst.Close()

		if _, err = dst.Write(content); err != nil {
			logUploadAttempt("SECURE_ERROR", "Dosya yazılamadı: "+err.Error(), header)
			http.Error(w, "Dosya yazılamadı", http.StatusInternalServerError)
			return
		}

		publicURL := "/uploads/" + secureFilename

		// Avatar güncellemesi isteniyorsa DB'ye yaz
		if isAvatar {
			if err := setAvatarForCurrentUser(r, publicURL, false /*secure*/); err != nil {
				logUploadAttempt("SECURE_WARN", "Avatar DB güncelleme hatası: "+err.Error(), header)
			}
			// Profil sayfasına yönlendir (cache-busting secure modda gerekmez ama istersen ekleyebilirsin)
			http.Redirect(w, r, "/profile.html?avatar_updated=1", http.StatusSeeOther)
			return
		}

		logUploadAttempt("SECURE_SUCCESS",
			fmt.Sprintf("Kaydedildi: orijinal=%s -> yeni=%s", header.Filename, secureFilename), header)

		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(publicURL))
		return

	} else {
		// ===== INSECURE MODE (bilerek zayıf kontroller) =====
		logUploadAttempt("INSECURE_START", "⚠️ Güvensiz mod aktif", header)

		// İçerik
		content, err := io.ReadAll(file)
		if err != nil {
			logUploadAttempt("INSECURE_ERROR", "Dosya okunamadı: "+err.Error(), header)
			http.Error(w, "Dosya okunamadı", http.StatusInternalServerError)
			return
		}

		// --- ZAYIF DOĞRULAMA ---
		// 1) SADECE istemci Content-Type'ına güven (spoof edilebilir)
		ct := header.Header.Get("Content-Type") // örn: image/gif

		// 2) Uydurma "uzantı kontrolü": adın herhangi bir yerinde .jpg/.jpeg/.png/.gif geçmesi yeterli
		looksLikeImageByName := naiveImageExtMatches(header.Filename)

		// 3) Sadece ilk byte'lara bakarak içerik tipini tahmin et (magic header ile kandırılabilir)
		sniff := http.DetectContentType(content)
		looksLikeImageBySniff := strings.HasPrefix(strings.ToLower(sniff), "image/")

		// Eğer bu üçünden herhangi biri doğruysa "resim" kabul et
		if !(strings.HasPrefix(strings.ToLower(ct), "image/") || looksLikeImageByName || looksLikeImageBySniff) {
			logUploadAttempt("INSECURE_BLOCK", "Zayıf kurala göre 'image' değil", header)
			http.Error(w, "Sadece resimler yüklenebilir (güvensiz kontrol)", http.StatusBadRequest)
			return
		}

		// Bypass denemelerini sadece logla (engelleme yok)
		_ = detectBypassHints(header.Filename, content, ct, sniff)

		// 4) PATH TRAVERSAL: Orijinal dosya adını aynen kullan (../, ..%2f vb. mümkün)
		dstPath := filepath.Join(uploadDir, header.Filename)
		_ = os.MkdirAll(filepath.Dir(dstPath), 0755)

		// Yaz (geniş izinler, içerik doğrulaması yok)
		dst, err := os.Create(dstPath)
		if err != nil {
			logUploadAttempt("INSECURE_ERROR", "Dosya oluşturulamadı: "+err.Error(), header)
			http.Error(w, "Dosya kaydedilemedi", http.StatusInternalServerError)
			return
		}
		defer dst.Close()

		if _, err = dst.Write(content); err != nil {
			logUploadAttempt("INSECURE_ERROR", "Dosya yazılamadı: "+err.Error(), header)
			http.Error(w, "Dosya yazılamadı", http.StatusInternalServerError)
			return
		}

		// Public URL (insecure: aynı isimle overwrite olabilir → cache-bust ekle)
		publicURL := "/uploads/" + header.Filename
		if isAvatar {
			// Cache'i kırmak için query param ekle (aynı isim yeniden yüklendiyse tarayıcı tazesini çeksin)
			publicURLWithBust := publicURL + "?v=" + fmt.Sprint(time.Now().Unix())
			if err := setAvatarForCurrentUser(r, publicURLWithBust, true /*insecure*/); err != nil {
				logUploadAttempt("INSECURE_WARN", "Avatar DB güncelleme hatası: "+err.Error(), header)
			}
			http.Redirect(w, r, "/profile.html?avatar_updated=1", http.StatusSeeOther)
			return
		}

		logUploadAttempt("INSECURE_SUCCESS",
			fmt.Sprintf("Kaydedildi (güvensiz): %s (%d bytes) ct=%s sniff=%s", header.Filename, len(content), ct, sniff), header)

		// Kullanıcıya görünür URL
		w.WriteHeader(http.StatusCreated)
		escaped := url.PathEscape(header.Filename)
		_, _ = w.Write([]byte("/uploads/" + escaped))
		return
	}
}

// ========== (IN)SECURE SERVE HANDLER ==========
/*
Router'da:
- En kolayı: her zaman handlers.ServeUpload'a bağla:
    r.Get("/uploads/*", handlers.ServeUpload)
  Fonksiyon mod'a göre davranır.
*/
func ServeUpload(w http.ResponseWriter, r *http.Request) {
	// Her iki modda da cache'i azalt (eski avatarın görünmesini önlemeye yardımcı)
	w.Header().Set("Cache-Control", "no-store, max-age=0, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	p := strings.TrimPrefix(r.URL.Path, "/uploads/")

	if mode.IsSecure() {
		// Güvenli: kök kilitli static server → traversal engelli
		http.StripPrefix("/uploads/", http.FileServer(http.Dir(uploadDir))).ServeHTTP(w, r)
		return
	}

	// Güvensiz: hiçbir doğrulama yapmadan join et ve sun → traversal açık
	if u, err := url.PathUnescape(p); err == nil {
		p = u // ..%2f gibi durumlar için
	}
	target := filepath.Join(uploadDir, p)
	http.ServeFile(w, r, target)
}

// ===== Yardımcılar =====

// Aktif kullanıcı adını JWT/cookie'den al
func currentUsername(r *http.Request) string {
	if claims, err := ParseJWT(r); err == nil {
		if u := fmt.Sprint(claims["username"]); u != "" && u != "<nil>" {
			return u
		}
	}
	if c, err := r.Cookie("user"); err == nil && c != nil && c.Value != "" {
		return c.Value
	}
	return ""
}

// Avatar URL'ini DB'ye yaz
func setAvatarForCurrentUser(r *http.Request, avatarURL string, insecure bool) error {
	uname := currentUsername(r)
	if uname == "" {
		return fmt.Errorf("current user not found")
	}
	_, err := DB.ExecContext(r.Context(),
		`UPDATE users SET avatar_url = ? WHERE username = ?`, avatarURL, uname)
	return err
}

// Naif ve kolay kandırılan "isimden uzantı" kontrolü
func naiveImageExtMatches(name string) bool {
	l := strings.ToLower(name)
	return strings.Contains(l, ".jpg") ||
		strings.Contains(l, ".jpeg") ||
		strings.Contains(l, ".png") ||
		strings.Contains(l, ".gif")
}

// Sadece log amaçlı ipuçları (engelleme yapmaz)
func detectBypassHints(filename string, content []byte, ctHeader string, sniff string) string {
	var hints []string
	lf := strings.ToLower(filename)

	// Content-Type spoof
	if strings.HasPrefix(strings.ToLower(ctHeader), "image/") {
		hints = append(hints, "CT-spoof")
	}

	// Double extension
	if strings.Count(lf, ".") >= 2 {
		hints = append(hints, "double-ext")
	}

	// %00 (uygulama seviyesinde kontrolleri şaşırtma girişimi)
	if strings.Contains(lf, "%00") || strings.Contains(filename, "\x00") {
		hints = append(hints, "null-byte")
	}

	// Magic header ile sniffing'i kandırma
	if strings.HasPrefix(strings.ToLower(sniff), "image/") {
		hints = append(hints, "magic-header/sniff")
	}

	// Basit script imzaları (sadece kayıt)
	c := strings.ToLower(string(content))
	for pattern, tag := range map[string]string{
		"<?php":       "php-code",
		"#!/bin/sh":   "sh-shebang",
		"#!/bin/bash": "bash-shebang",
		"<script":     "html-js",
	} {
		if strings.Contains(c, pattern) {
			hints = append(hints, tag)
		}
	}

	if len(hints) == 0 {
		return "no-hints"
	}
	msg := "bypass-hints: " + strings.Join(hints, ",")
	logUploadAttempt("INSECURE_HINTS", msg, &multipart.FileHeader{Filename: filename})
	return msg
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func containsMime(slice []string, item string) bool {
	for _, s := range slice {
		if strings.HasPrefix(item, s) {
			return true
		}
	}
	return false
}

func logUploadAttempt(action, message string, header *multipart.FileHeader) {
	var filename string
	if header != nil {
		filename = header.Filename
	} else {
		filename = "unknown"
	}
	logMsg := fmt.Sprintf("[%s] %s - File: %s", action, message, filename)
	log.Println(logMsg)
	logToFile(action, logMsg)
}

func logToFile(action, message string) {
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	_, _ = f.WriteString(fmt.Sprintf("[%s] %s: %s\n", timestamp, action, message))
}
