package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	stdhttp "net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"secureshift/internal/mode"

	"golang.org/x/crypto/bcrypt"
)

// küçük yardımcı: insecure dalda tek tırnak kaçır (SQLite uyumlu)
func escSQL(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

func ProfileGet(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	claims, err := ParseJWT(r)
	if err != nil {
		stdhttp.Error(w, "Unauthorized", stdhttp.StatusUnauthorized)
		return
	}
	username := fmt.Sprint(claims["username"])

	var firstname, lastname, city, avatar string
	err = DB.QueryRowContext(r.Context(),
		`SELECT COALESCE(firstname,''), COALESCE(lastname,''), COALESCE(city,''), COALESCE(avatar,'')
		 FROM users WHERE username = ?`, username).
		Scan(&firstname, &lastname, &city, &avatar)
	if err != nil {
		if err == sql.ErrNoRows {
			stdhttp.Error(w, "Profile not found", stdhttp.StatusNotFound)
			return
		}
		stdhttp.Error(w, "DB error", stdhttp.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"username":  username,
		"firstname": firstname,
		"lastname":  lastname,
		"city":      city,
		"avatar":    avatar,
	})
}

func ProfilePost(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	claims, err := ParseJWT(r)
	if err != nil {
		stdhttp.Error(w, "Unauthorized", stdhttp.StatusUnauthorized)
		return
	}
	username := fmt.Sprint(claims["username"])

	if err := r.ParseMultipartForm(20 << 20); err != nil { // 20MB
		stdhttp.Error(w, "Bad form", stdhttp.StatusBadRequest)
		return
	}

	firstname := r.FormValue("firstname")
	lastname := r.FormValue("lastname")
	city := r.FormValue("city")

	// 👇 insecure modda role manipülasyonu için alınıyor
	role := r.FormValue("role")

	avatarFile, header, err := r.FormFile("avatar")
	avatarFilename := ""
	if err == nil {
		defer avatarFile.Close()
		insecureDir := "./web/uploads"
		secureDir := "./web/uploads/avatars"
		_ = os.MkdirAll(insecureDir, 0755)
		_ = os.MkdirAll(secureDir, 0755)

		if mode.IsSecure() {
			// ✅ SECURE: MIME + uzantı + güvenli isim
			buf := make([]byte, 512)
			n, _ := avatarFile.Read(buf)
			mime := stdhttp.DetectContentType(buf[:n])
			if !(strings.HasPrefix(mime, "image/jpeg") || strings.HasPrefix(mime, "image/png")) {
				stdhttp.Error(w, "Only JPEG/PNG allowed", stdhttp.StatusBadRequest)
				return
			}
			if _, err := avatarFile.Seek(0, 0); err != nil {
				stdhttp.Error(w, "seek fail", stdhttp.StatusInternalServerError)
				return
			}
			ext := strings.ToLower(filepath.Ext(header.Filename))
			if ext != ".jpg" && ext != ".jpeg" && ext != ".png" {
				stdhttp.Error(w, "Invalid extension", stdhttp.StatusBadRequest)
				return
			}
			safeName := fmt.Sprintf("%s_%d%s", username, time.Now().UnixNano(), ext)
			dstPath := filepath.Join(secureDir, safeName)
			dst, err := os.Create(dstPath)
			if err != nil {
				stdhttp.Error(w, "save fail", stdhttp.StatusInternalServerError)
				return
			}
			defer dst.Close()
			if _, err := io.Copy(dst, avatarFile); err != nil {
				stdhttp.Error(w, "write fail", stdhttp.StatusInternalServerError)
				return
			}
			avatarFilename = "uploads/avatars/" + safeName
		} else {
			// ❌ INSECURE: kontrolsüz kayıt
			rawName := header.Filename
			if rawName == "" {
				rawName = "avatar"
			}
			dstPath := insecureDir + "/" + rawName
			dst, err := os.Create(dstPath)
			if err != nil {
				stdhttp.Error(w, "save fail", stdhttp.StatusInternalServerError)
				return
			}
			defer dst.Close()
			_, _ = io.Copy(dst, avatarFile)
			avatarFilename = "uploads/" + rawName
		}
	}

	// DB güncelle
	var execErr error
	if mode.IsSecure() {
		// ✅ SECURE: role asla değişmez
		if avatarFilename != "" {
			_, execErr = DB.ExecContext(r.Context(),
				`UPDATE users SET firstname=?, lastname=?, city=?, avatar=? WHERE username=?`,
				firstname, lastname, city, avatarFilename, username)
		} else {
			_, execErr = DB.ExecContext(r.Context(),
				`UPDATE users SET firstname=?, lastname=?, city=? WHERE username=?`,
				firstname, lastname, city, username)
		}
	} else {
		// ❌ INSECURE: saldırgan role alanını da değiştirebilir
		set := fmt.Sprintf("firstname='%s', lastname='%s', city='%s'",
			escSQL(firstname), escSQL(lastname), escSQL(city))

		if role != "" {
			set += fmt.Sprintf(", role='%s'", escSQL(role))
		}

		if avatarFilename != "" {
			set += fmt.Sprintf(", avatar='%s'", escSQL(avatarFilename))
		}

		q := fmt.Sprintf(`UPDATE users SET %s WHERE username='%s'`, set, escSQL(username))
		_, execErr = DB.ExecContext(r.Context(), q)
	}

	if execErr != nil {
		log.Printf("profile update error: %v", execErr)
		stdhttp.Error(w, "Update failed", stdhttp.StatusInternalServerError)
		return
	}

	stdhttp.Redirect(w, r, "/profile.html?ok=1", stdhttp.StatusSeeOther)
}

// ===== /api/password-reset =====
// Secure mod: SADECE POST + bcrypt
// Insecure mod: POST ve (CSRF demo için) GET kabul, plaintext yaz
func PasswordReset(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	claims, err := ParseJWT(r)
	if err != nil {
		stdhttp.Error(w, "Unauthorized", stdhttp.StatusUnauthorized)
		return
	}
	username := fmt.Sprint(claims["username"])

	if mode.IsSecure() && r.Method != stdhttp.MethodPost {
		stdhttp.Error(w, "Method Not Allowed", stdhttp.StatusMethodNotAllowed)
		return
	}

	var newPassword string
	if !mode.IsSecure() && r.Method == stdhttp.MethodGet {
		newPassword = r.URL.Query().Get("password")
	} else {
		if err := r.ParseForm(); err != nil {
			stdhttp.Error(w, "Bad form", stdhttp.StatusBadRequest)
			return
		}
		newPassword = r.FormValue("password")
	}

	if strings.TrimSpace(newPassword) == "" {
		stdhttp.Error(w, "Password required", stdhttp.StatusBadRequest)
		return
	}

	var execErr error
	if mode.IsSecure() {
		hashed, hErr := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if hErr != nil {
			stdhttp.Error(w, "Hashing failed", stdhttp.StatusInternalServerError)
			return
		}
		_, execErr = DB.ExecContext(r.Context(),
			"UPDATE users SET password=? WHERE username=?",
			string(hashed), username)
	} else {
		q := fmt.Sprintf("UPDATE users SET password='%s' WHERE username='%s'",
			escSQL(newPassword), escSQL(username))
		_, execErr = DB.ExecContext(r.Context(), q)
	}

	if execErr != nil {
		log.Printf("password reset error: %v", execErr)
		stdhttp.Error(w, "DB update failed", stdhttp.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  "ok",
		"message": "Password updated",
	})
}

/* =========================
   URL'den Avatar Yükleme (SSRF Demo)
   Endpoint: POST /api/avatar-from-url
   - Insecure:
       * Her türlü host/şema serbest (http/https + isteğe bağlı file:// vb. engellenmiyor)
       * Kullanıcının Cookie/Authorization header'ları iç isteğe FORWARD edilir (SSRF ile yetki taşıma gösterimi)
       * İsteğe özel method/body/content-type geçilebilir → /admin/ping'e POST ile gidebilirsin
       * İndirilen içerik türü kontrol edilmez; dosya /web/uploads altına kaydedilir, avatar alanına set edilebilir
   - Secure:
       * Sadece http/https
       * Host IP'si resolve edilip PRIVATE/LOOPBACK/LINK-LOCAL vs BLOCK
       * Sadece GET yapılır, header forward edilmez
       * Sadece image/jpeg, image/png kabul edilir; /web/uploads/avatars altına kaydedilir
========================= */

type avatarFromURLReq struct {
	URL         string `json:"url"`
	Method      string `json:"method,omitempty"`      // insecure
	ContentType string `json:"contentType,omitempty"` // insecure
	Body        string `json:"body,omitempty"`        // insecure
}

type avatarFromURLResp struct {
	Avatar       string `json:"avatar,omitempty"`
	SavedAs      string `json:"saved_as,omitempty"`
	HTTPStatus   int    `json:"http_status,omitempty"`
	ContentType  string `json:"content_type,omitempty"`
	Size         int    `json:"size,omitempty"`
	Error        string `json:"error,omitempty"`
	Mode         string `json:"mode"`
	Note         string `json:"note,omitempty"`
	RedirectedTo string `json:"redirected_to,omitempty"`
}

func AvatarFromURL(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	claims, err := ParseJWT(r)
	if err != nil {
		writerJSON(w, stdhttp.StatusUnauthorized, avatarFromURLResp{Error: "Unauthorized"})
		return
	}
	username := fmt.Sprint(claims["username"])

	// isteği oku (JSON ya da form)
	var in avatarFromURLReq
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.HasPrefix(ct, "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writerJSON(w, stdhttp.StatusBadRequest, avatarFromURLResp{Error: "Geçersiz JSON"})
			return
		}
	} else {
		if err := r.ParseForm(); err != nil {
			writerJSON(w, stdhttp.StatusBadRequest, avatarFromURLResp{Error: "Form parse edilemedi"})
			return
		}
		in.URL = r.FormValue("url")
		in.Method = r.FormValue("method")
		in.ContentType = r.FormValue("contentType")
		in.Body = r.FormValue("body")
	}

	in.URL = strings.TrimSpace(in.URL)
	if in.URL == "" {
		writerJSON(w, stdhttp.StatusBadRequest, avatarFromURLResp{Error: "URL gerekli"})
		return
	}

	// dizinler
	insecureDir := "./web/uploads"
	secureDir := "./web/uploads/avatars"
	_ = os.MkdirAll(insecureDir, 0755)
	_ = os.MkdirAll(secureDir, 0755)

	// HTTP client
	client := &stdhttp.Client{
		Timeout: 12 * time.Second,
	}

	// request hazırla
	var req *stdhttp.Request
	var fetchURL *url.URL
	var parseErr error
	if fetchURL, parseErr = url.Parse(in.URL); parseErr != nil {
		writerJSON(w, stdhttp.StatusBadRequest, avatarFromURLResp{Error: "URL parse edilemedi"})
		return
	}

	// SECURE davranış: sadece http/https + internal IP block + sadece GET + header forward YOK
	if mode.IsSecure() {
		if !isAllowedSchemeSecure(fetchURL.Scheme) {
			writerJSON(w, stdhttp.StatusBadRequest, avatarFromURLResp{Error: "Yalnızca http/https şeması kabul edilir", Mode: "secure"})
			return
		}
		if isBlockedHostSecure(r.Context(), fetchURL.Hostname()) {
			writerJSON(w, stdhttp.StatusForbidden, avatarFromURLResp{Error: "Hedef host izinli değil", Mode: "secure"})
			return
		}

		req, err = stdhttp.NewRequestWithContext(r.Context(), stdhttp.MethodGet, in.URL, nil)
		if err != nil {
			writerJSON(w, stdhttp.StatusBadRequest, avatarFromURLResp{Error: "İstek oluşturulamadı", Mode: "secure"})
			return
		}
	} else {
		// INSECURE davranış:
		// - method/body/content-type serbest
		method := strings.ToUpper(strings.TrimSpace(in.Method))
		if method == "" {
			method = stdhttp.MethodGet
		}
		var body io.Reader
		if in.Body != "" {
			body = strings.NewReader(in.Body)
		}
		req, err = stdhttp.NewRequestWithContext(r.Context(), method, in.URL, body)
		if err != nil {
			writerJSON(w, stdhttp.StatusBadRequest, avatarFromURLResp{Error: "İstek oluşturulamadı", Mode: "insecure"})
			return
		}
		if in.ContentType != "" {
			req.Header.Set("Content-Type", in.ContentType)
		}

		// ⚠️ INSECURE: dış isteğe kullanıcının Cookie/Authorization header'ını forward et
		if c, err := r.Cookie("token"); err == nil {
			req.AddCookie(c)
		}
		if auth := r.Header.Get("Authorization"); auth != "" {
			req.Header.Set("Authorization", auth)
		}
	}

	// fetch
	resp, err := client.Do(req)
	if err != nil {
		writerJSON(w, stdhttp.StatusBadGateway, avatarFromURLResp{Error: "Fetch başarısız", Mode: modeLabel(), Note: err.Error()})
		return
	}
	defer resp.Body.Close()

	// redirect bilgisi (gözlem amaçlı)
	finalURL := resp.Request.URL.String()
	ctResp := strings.ToLower(resp.Header.Get("Content-Type"))

	// veriyi limitleyerek oku
	const maxSize = int64(10 << 20) // 10MB
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, io.LimitReader(resp.Body, maxSize)); err != nil {
		writerJSON(w, stdhttp.StatusInternalServerError, avatarFromURLResp{Error: "İçerik okunamadı", Mode: modeLabel()})
		return
	}
	data := buf.Bytes()

	var avatarPath string
	var savedAs string

	if mode.IsSecure() {
		// ✅ SECURE: sadece jpeg/png kabul
		if !(strings.HasPrefix(ctResp, "image/jpeg") || strings.HasPrefix(ctResp, "image/png")) {
			writerJSON(w, stdhttp.StatusBadRequest, avatarFromURLResp{
				Error:       "Yalnızca JPEG/PNG içerik indirilebilir",
				Mode:        "secure",
				HTTPStatus:  resp.StatusCode,
				ContentType: ctResp,
			})
			return
		}
		ext := ".img"
		if strings.HasPrefix(ctResp, "image/jpeg") {
			ext = ".jpg"
		} else if strings.HasPrefix(ctResp, "image/png") {
			ext = ".png"
		}
		safeName := fmt.Sprintf("%s_url_%d%s", username, time.Now().UnixNano(), ext)
		dstPath := filepath.Join(secureDir, safeName)
		if err := os.WriteFile(dstPath, data, 0644); err != nil {
			writerJSON(w, stdhttp.StatusInternalServerError, avatarFromURLResp{Error: "Kayıt başarısız", Mode: "secure"})
			return
		}
		avatarPath = "uploads/avatars/" + safeName
		savedAs = dstPath

		// DB'ye yaz
		if _, err := DB.ExecContext(r.Context(), `UPDATE users SET avatar=? WHERE username=?`, avatarPath, username); err != nil {
			writerJSON(w, stdhttp.StatusInternalServerError, avatarFromURLResp{Error: "DB update failed", Mode: "secure"})
			return
		}

		writerJSON(w, stdhttp.StatusOK, avatarFromURLResp{
			Mode:        "secure",
			Avatar:      avatarPath,
			SavedAs:     savedAs,
			HTTPStatus:  resp.StatusCode,
			ContentType: ctResp,
			Size:        len(data),
			Note:        "Yalnızca resimler kabul edildi",
		})
		return
	}

	// ❌ INSECURE: içerik türü/host kontrolü YOK, her şeyi kaydet
	filename := path.Base(fetchURL.Path)
	if filename == "" || filename == "/" || filename == "." {
		filename = fmt.Sprintf("%s_url_%d.bin", username, time.Now().UnixNano())
	}
	dstPath := filepath.Join(insecureDir, filename)
	if err := os.WriteFile(dstPath, data, 0644); err != nil {
		writerJSON(w, stdhttp.StatusInternalServerError, avatarFromURLResp{Error: "Kayıt başarısız", Mode: "insecure"})
		return
	}
	avatarPath = "uploads/" + filename
	savedAs = dstPath

	// Avatar alanına direkt yaz (image olup olmamasına bakmadan)
	if _, err := DB.ExecContext(r.Context(), `UPDATE users SET avatar=? WHERE username=?`, avatarPath, username); err != nil {
		writerJSON(w, stdhttp.StatusInternalServerError, avatarFromURLResp{Error: "DB update failed", Mode: "insecure"})
		return
	}

	writerJSON(w, stdhttp.StatusOK, avatarFromURLResp{
		Mode:         "insecure",
		Avatar:       avatarPath,
		SavedAs:      savedAs,
		HTTPStatus:   resp.StatusCode,
		ContentType:  ctResp,
		Size:         len(data),
		RedirectedTo: finalURL,
		Note:         "Header forward + method/body serbest; image kontrolü yok",
	})
}

// ===== Helpers (SSRF Secure kontrolleri) =====

func modeLabel() string {
	if mode.IsSecure() {
		return "secure"
	}
	return "insecure"
}

func isAllowedSchemeSecure(s string) bool {
	s = strings.ToLower(s)
	return s == "http" || s == "https"
}

func isBlockedHostSecure(ctx context.Context, host string) bool {
	// localhost ve kısa yollar
	lh := strings.ToLower(host)
	if lh == "localhost" || lh == "metadata" {
		return true
	}

	// IP olarak parse ediliyorsa direkt değerlendir
	if ip := net.ParseIP(host); ip != nil {
		return isPrivateOrSpecialIP(ip)
	}

	// DNS resolve et ve IP'leri kontrol et
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		// resolve edilemiyorsa güvenlik gereği engelle
		return true
	}
	for _, ipa := range ips {
		if isPrivateOrSpecialIP(ipa.IP) {
			return true
		}
	}
	return false
}

func isPrivateOrSpecialIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	// 169.254.0.0/16 (metadata'a yakın link-local), 127.0.0.0/8, fc00::/7 vb. zaten üstte çoğu kapsandı
	// Ek özel kontrol: 169.254.169.254 (cloud metadata)
	if ip.To4() != nil {
		if ip[0] == 169 && ip[1] == 254 {
			return true
		}
	}
	return false
}

// ortak JSON yazıcı
func writerJSON(w stdhttp.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
