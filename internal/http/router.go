package http

import (
	stdhttp "net/http"
	"strings"

	"secureshift/internal/handlers"
	"secureshift/internal/mode"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Sadece token cookie var mı diye bakar; secure modda token'ı da doğrular.
func authRequired(next stdhttp.Handler) stdhttp.Handler {
	return stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		// Cookie veya Authorization: Bearer kabul et
		token := ""
		if c, err := r.Cookie("token"); err == nil {
			token = c.Value
		}
		if token == "" {
			authz := r.Header.Get("Authorization")
			if strings.HasPrefix(strings.ToLower(authz), "bearer ") {
				token = strings.TrimSpace(authz[7:])
			}
		}
		if token == "" {
			stdhttp.Redirect(w, r, "/index.html", stdhttp.StatusSeeOther)
			return
		}
		// Secure modda imzayı gerçekten doğrula
		if mode.IsSecure() {
			if _, err := handlers.ParseJWT(r); err != nil {
				stdhttp.Redirect(w, r, "/index.html", stdhttp.StatusSeeOther)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// Admin yetkisi kontrolü - backend'de gerçek admin kontrolü
func adminRequired(next stdhttp.Handler) stdhttp.Handler {
	return stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		// Önce auth kontrolü yap
		token := ""
		if c, err := r.Cookie("token"); err == nil {
			token = c.Value
		}
		if token == "" {
			authz := r.Header.Get("Authorization")
			if strings.HasPrefix(strings.ToLower(authz), "bearer ") {
				token = strings.TrimSpace(authz[7:])
			}
		}
		if token == "" {
			stdhttp.Redirect(w, r, "/index.html", stdhttp.StatusSeeOther)
			return
		}

		// Secure modda JWT kontrolü
		if mode.IsSecure() {
			if _, err := handlers.ParseJWT(r); err != nil {
				stdhttp.Redirect(w, r, "/index.html", stdhttp.StatusSeeOther)
				return
			}
		}

		// User bilgilerini al ve admin kontrolü yap
		user, err := handlers.GetUserFromRequest(r)
		if err != nil {
			stdhttp.Redirect(w, r, "/index.html", stdhttp.StatusSeeOther)
			return
		}

		// Admin kontrolü
		if user.Role != "admin" {
			// JSON request ise JSON response döndür
			if strings.Contains(r.Header.Get("Content-Type"), "application/json") ||
				strings.Contains(r.Header.Get("Accept"), "application/json") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(stdhttp.StatusForbidden)
				w.Write([]byte(`{"error": "Bu işlem için admin yetkisi gereklidir"}`))
				return
			}
			// HTML request ise dashboard'a yönlendir
			stdhttp.Redirect(w, r, "/dashboard.html", stdhttp.StatusSeeOther)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func NewRouter() stdhttp.Handler {
	r := chi.NewRouter()

	// ---- Middleware'ler ----
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// ---- Dinamik endpoint'ler ----
	r.Post("/login", handlers.Login)
	r.Get("/logout", handlers.Logout)

	// ==== PRODUCT DETAIL ====
	r.Get("/product-detail.html", handlers.ProductDetailHandler)

	r.Post("/comment", handlers.AddComment)

	// Upload handler
	r.Post("/upload", handlers.FileUpload)

	// Upload edilen dosyaları servis etme (mode'a göre)
	if mode.IsSecure() {
		fsUploads := stdhttp.StripPrefix("/uploads/", stdhttp.FileServer(stdhttp.Dir("./web/uploads")))
		r.Get("/uploads/*", func(w stdhttp.ResponseWriter, req *stdhttp.Request) {
			fsUploads.ServeHTTP(w, req)
		})
	} else {
		r.Get("/uploads/*", handlers.ServeUpload)
	}

	// ==== PRODUCTS (YENİ) ====
	r.Get("/products", handlers.ProductsHandler)
	r.Get("/products.html", handlers.ProductsHandler)

	// ---- Faturalar (Path Traversal + IDOR) ----
	r.With(authRequired).Get("/invoices.html", func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		stdhttp.ServeFile(w, r, "./web/invoices.html")
	})
	r.With(authRequired).Get("/downloadFile", handlers.DownloadInvoice)

	// ---- Admin Paneli ----
	r.With(adminRequired).Get("/admin.html", func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		stdhttp.ServeFile(w, r, "./web/admin.html")
	})
	r.With(adminRequired).Post("/admin/ping", handlers.AdminPing)

	// ===== API ENDPOINTS - Tümü korumalı =====
	r.With(authRequired).Get("/api/whoami", handlers.WhoAmI)
	r.With(authRequired).Get("/api/profile", handlers.ProfileGet)

	// Profil metin alanları (şifre hariç)
	r.With(authRequired).Post("/profile", handlers.ProfilePost)

	// 🔑 Şifre reset
	r.With(authRequired).Post("/api/password-reset", handlers.PasswordReset)
	if !mode.IsSecure() {
		// sadece insecure modda GET aç
		r.With(authRequired).Get("/api/password-reset", handlers.PasswordReset)
	}

	// 🔗 URL'den avatar (SSRF demo)
	r.With(authRequired).Post("/api/avatar-from-url", handlers.AvatarFromURL)

	// 💬 ChatBot (SSTI demo)
	r.With(authRequired).Post("/api/chatbot", handlers.ChatBotHandler)

	// 📄 About (XXE demo)
	r.With(authRequired).Get("/api/about-xml", handlers.AboutHandler)
	r.With(authRequired).Post("/api/about-xml", handlers.AboutHandler)

	r.With(authRequired).Get("/api/invoices", handlers.ListUserInvoices)

	// ===== Korumalı HTML sayfaları =====
	r.With(authRequired).Get("/dashboard.html", func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		stdhttp.ServeFile(w, r, "./web/dashboard.html")
	})
	r.With(authRequired).Get("/profile.html", func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		stdhttp.ServeFile(w, r, "./web/profile.html")
	})
	r.Get("/about.html", func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		stdhttp.ServeFile(w, r, "./web/about.html")
	})

	// ===== Ana sayfa =====
	r.Get("/", handlers.Home)

	// ===== Statik dosyalar (EN SONA KOY) =====
	fs := stdhttp.FileServer(stdhttp.Dir("./web"))
	r.With(middleware.NoCache).Handle("/*", fs)

	return r
}
