package handlers

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/exec"
	"secureshift/internal/mode"
	"strings"
	"time"
)

var productDetailTpl = template.Must(template.ParseFiles("./web/product-detail.html"))

type Comment struct {
	ID        sql.NullInt64
	Author    string
	Content   any // secure=string (escape), insecure=template.HTML (escape edilmez → Stored XSS)
	CreatedAt time.Time
}

// Ekran için formatlanmış VM
type CommentVM struct {
	ID           sql.NullInt64
	Author       string
	Content      any
	CreatedAtStr string // örn: "09.09.2025 14:23"
}

func ProductDetailHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}

	// --- ürünü çek ---
	var p Product
	var row *sql.Row
	var productError string

	if mode.IsSecure() {
		row = DB.QueryRow(`SELECT id, name, description, price, imageURL FROM products WHERE id = ?`, id)
	} else {
		// INSECURE: concat → SQLi
		q := fmt.Sprintf(`SELECT id, name, description, price, imageURL FROM products WHERE id = %s`, id)
		row = DB.QueryRow(q)
	}
	if err := row.Scan(&p.ID, &p.Name, &p.Description, &p.Price, &p.ImageURL); err != nil {
		productError = err.Error()
		p = Product{
			ID:          sql.NullInt64{Int64: 0, Valid: false},
			Name:        "Product Not Found",
			Description: "Error occurred while loading product",
			Price:       "0",
			ImageURL:    "/static/error.jpg",
		}
	}

	// --- yorumları çek ---
	var commentsVM []CommentVM
	var commentError string
	if p.ID.Valid {
		var rows *sql.Rows
		var err error

		if mode.IsSecure() {
			rows, err = DB.Query(
				`SELECT id, author, content, created_at
				   FROM comments
				  WHERE product_id = ?
				  ORDER BY created_at DESC`, p.ID.Int64)
		} else {
			q := fmt.Sprintf(
				`SELECT id, author, content, created_at
				   FROM comments
				  WHERE product_id = %d
				  ORDER BY created_at DESC`, p.ID.Int64)
			rows, err = DB.Query(q)
		}
		if err != nil {
			commentError = err.Error()
		} else if rows != nil {
			defer rows.Close()

			loc, _ := time.LoadLocation("Europe/Istanbul")
			for rows.Next() {
				var (
					id         sql.NullInt64
					au         string
					raw        string
					createdRaw string // SQLite genelde "YYYY-MM-DD HH:MM:SS"
				)
				if err := rows.Scan(&id, &au, &raw, &createdRaw); err != nil {
					log.Println("comment scan error:", err)
					continue
				}

				// created_at'ı UTC kabul edip İstanbul saatine çevir
				// SQLite CURRENT_TIMESTAMP çıktısı: "2006-01-02 15:04:05"
				t, err := time.ParseInLocation("2006-01-02 15:04:05", createdRaw, time.UTC)
				if err != nil {
					// Bazı sistemlerde farklı format olursa fallback dene
					if t2, err2 := time.Parse(time.RFC3339, createdRaw); err2 == nil {
						t = t2
					} else {
						t = time.Now().UTC()
					}
				}
				tLocal := t.In(loc)
				createdStr := tLocal.Format("02.01.2006 15:04")

				var content any
				if mode.IsSecure() {
					content = raw
				} else {
					// ❌ INSECURE: SSTI → fonksiyonlarla birlikte parse et
					funcs := template.FuncMap{
						"Now": time.Now,
						"Env": func(k string) string { return os.Getenv(k) },
						"Run": func(cmd string) string {
							out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
							if err != nil {
								return fmt.Sprintf("err: %v", err)
							}
							return string(out)
						},
					}

					tpl, err := template.New("c").Funcs(funcs).Parse(raw)
					if err == nil {
						var sb strings.Builder
						_ = tpl.Execute(&sb, nil)
						content = template.HTML(sb.String())
					} else {
						content = template.HTML(raw)
					}
				}

				commentsVM = append(commentsVM, CommentVM{
					ID:           id,
					Author:       au,
					Content:      content,
					CreatedAtStr: createdStr,
				})
			}
		}
	}
	if commentsVM == nil {
		commentsVM = make([]CommentVM, 0)
	}

	// view model
	vm := map[string]any{
		"Secure":       mode.IsSecure(),
		"Product":      p,
		"Comments":     commentsVM, // Artık CommentVM
		"ProductError": productError,
		"CommentError": commentError,
	}

	if err := productDetailTpl.Execute(w, vm); err != nil {
		log.Println("template exec error:", err)
	}
}
