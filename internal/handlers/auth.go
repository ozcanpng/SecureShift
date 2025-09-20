package handlers

import (
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"secureshift/internal/mode"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var DB *sql.DB // main.go'da set ediliyor

// global secret key
var jwtKey = []byte("supersecret") // secure modda güçlü, insecure modda basit/none

// === yardımcı: istekten JWT çek ===
func extractIncomingToken(r *http.Request) string {
	// 1) Form alanı: token
	if t := r.FormValue("token"); t != "" {
		return t
	}
	// 2) Authorization: Bearer <token>
	authz := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(authz), "bearer ") {
		return strings.TrimSpace(authz[7:])
	}
	return ""
}

// === LOGIN ===
func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	incomingToken := extractIncomingToken(r)
	if incomingToken != "" {
		// === TOKEN ile giriş akışı ===
		if mode.IsSecure() {
			token, err := jwt.Parse(incomingToken, func(t *jwt.Token) (interface{}, error) {
				if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method")
				}
				return jwtKey, nil
			})
			if err != nil || !token.Valid {
				http.Redirect(w, r, "/login.html?error=login_failed", http.StatusSeeOther)
				return
			}
			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				http.Redirect(w, r, "/login.html?error=login_failed", http.StatusSeeOther)
				return
			}

			tokenUsername := fmt.Sprint(claims["username"])

			row := DB.QueryRowContext(r.Context(),
				`SELECT username, role FROM users WHERE username = ?`, tokenUsername)

			var dbUsername, dbRole string
			if err := row.Scan(&dbUsername, &dbRole); err != nil {
				http.Redirect(w, r, "/login.html?error=login_failed", http.StatusSeeOther)
				return
			}

			newTok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"username": dbUsername,
				"role":     dbRole,
				"exp":      time.Now().Add(time.Hour).Unix(),
			})
			ts, err := newTok.SignedString(jwtKey)
			if err != nil {
				http.Error(w, "JWT creation failed", http.StatusInternalServerError)
				return
			}

			http.SetCookie(w, &http.Cookie{
				Name:     "token",
				Value:    ts,
				Path:     "/",
				HttpOnly: true,
			})
			http.SetCookie(w, &http.Cookie{
				Name:  "user",
				Value: dbUsername,
				Path:  "/",
			})

			http.Redirect(w, r, "/dashboard.html?success=true", http.StatusSeeOther)
			return
		} else {
			tok, _, err := new(jwt.Parser).ParseUnverified(incomingToken, jwt.MapClaims{})
			var uname, role string
			if err != nil {
				uname = r.FormValue("username")
				role = r.FormValue("role")
				if uname == "" {
					uname = "user"
				}
				if role == "" {
					role = "user"
				}
			} else {
				if c, ok := tok.Claims.(jwt.MapClaims); ok {
					uname = fmt.Sprint(c["username"])
					role = fmt.Sprint(c["role"])
					if uname == "" || uname == "<nil>" {
						uname = "user"
					}
					if role == "" || role == "<nil>" {
						role = "user"
					}
				}
			}

			claims := jwt.MapClaims{
				"username": uname,
				"role":     role,
			}
			newToken := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
			ts, _ := newToken.SignedString(jwt.UnsafeAllowNoneSignatureType)

			http.SetCookie(w, &http.Cookie{
				Name:     "token",
				Value:    ts,
				Path:     "/",
				HttpOnly: false,
			})
			http.SetCookie(w, &http.Cookie{
				Name:  "user",
				Value: uname,
				Path:  "/",
			})

			http.Redirect(w, r, "/dashboard.html?success=true", http.StatusSeeOther)
			return
		}
	}

	// === username/password ile giriş ===
	username := r.FormValue("username")
	password := r.FormValue("password")

	// ✅ PAROLA DOĞRULAMA: VerifyUserPassword kullan
	ok, err := VerifyUserPassword(r.Context(), username, password)
	if err != nil {
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Redirect(w, r, "/login.html?error=login_failed", http.StatusSeeOther)
		return
	}

	// Parola doğrulandı → role almak için kullanıcıyı çek
	row := DB.QueryRowContext(r.Context(),
		`SELECT username, role FROM users WHERE username = ?`, username)

	var dbUsername, dbRole string
	if err := row.Scan(&dbUsername, &dbRole); err != nil {
		http.Redirect(w, r, "/login.html?error=login_failed", http.StatusSeeOther)
		return
	}

	// Token üret
	if mode.IsSecure() {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"username": dbUsername,
			"role":     dbRole,
			"exp":      time.Now().Add(time.Hour).Unix(),
		})
		ts, err := token.SignedString(jwtKey)
		if err != nil {
			http.Error(w, "JWT creation failed", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "token",
			Value:    ts,
			Path:     "/",
			HttpOnly: true,
		})
		http.SetCookie(w, &http.Cookie{
			Name:  "user",
			Value: dbUsername,
			Path:  "/",
		})

		http.Redirect(w, r, "/dashboard.html?success=true", http.StatusSeeOther)
		return
	}

	// insecure mod token
	claims := jwt.MapClaims{
		"username": dbUsername,
		"role":     dbRole,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	ts, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		http.Error(w, "JWT creation failed", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    ts,
		Path:     "/",
		HttpOnly: false,
	})
	http.SetCookie(w, &http.Cookie{
		Name:  "user",
		Value: dbUsername,
		Path:  "/",
	})

	http.Redirect(w, r, "/dashboard.html?success=true", http.StatusSeeOther)
}

// === LOGOUT ===
func Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   "token",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name:   "user",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/login.html", http.StatusSeeOther)
}

// === JWT Verify Helper ===
func ParseJWT(r *http.Request) (map[string]interface{}, error) {
	c, err := r.Cookie("token")
	if err != nil {
		return nil, err
	}
	tokenString := c.Value

	if mode.IsSecure() {
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return jwtKey, nil
		})
		if err != nil {
			return nil, err
		}
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			return claims, nil
		}
		return nil, fmt.Errorf("invalid token")
	} else {
		token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
		if err != nil {
			return nil, err
		}
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			return claims, nil
		}
		return nil, fmt.Errorf("invalid token (insecure)")
	}
}

// === /api/whoami ===
func WhoAmI(w http.ResponseWriter, r *http.Request) {
	claims, err := ParseJWT(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	username := fmt.Sprint(claims["username"])
	role := fmt.Sprint(claims["role"])
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, fmt.Sprintf(`{"username":%q,"role":%q}`, username, role))
}
