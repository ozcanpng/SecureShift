package handlers

import (
	"database/sql"
	"fmt"
	"html"
	"net/http"
	"strconv"
	"strings"
	"time"

	"secureshift/internal/mode"
)

// ListComments: (opsiyonel) tüm yorumları dönen basit debug görünümü.
// İstersen router’dan GET /comment’i kaldırabilirsin.
func ListComments(w http.ResponseWriter, r *http.Request) {
	rows, err := DB.Query(`SELECT id, product_id, author, content, created_at FROM comments ORDER BY created_at DESC LIMIT 100`)
	if err != nil {
		http.Error(w, "query error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type rowT struct {
		id        sql.NullInt64
		productID sql.NullInt64
		author    string
		content   string
		createdAt time.Time
	}
	var all []rowT
	for rows.Next() {
		var x rowT
		if err := rows.Scan(&x.id, &x.productID, &x.author, &x.content, &x.createdAt); err == nil {
			all = append(all, x)
		}
	}

	// Çok basit bir HTML liste; sadece debug için.
	var b strings.Builder
	b.WriteString("<h3>Comments</h3>")
	for _, c := range all {
		if mode.IsSecure() {
			// secure: ekranda kaçışla göster
			b.WriteString("<div><b>")
			b.WriteString(html.EscapeString(c.author))
			b.WriteString(":</b> ")
			b.WriteString(html.EscapeString(c.content))
			b.WriteString("</div>")
		} else {
			// insecure: KAÇIŞ YOK (Stored XSS burada da görülür)
			b.WriteString("<div><b>")
			b.WriteString(c.author)
			b.WriteString(":</b> ")
			b.WriteString(c.content)
			b.WriteString("</div>")
		}
	}
	b.WriteString(`<p class="mt-3"><a href="/products.html">Ürünlere dön</a></p>`)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(b.String()))
}

// AddComment: ürüne yorum ekler ve ürün detayına döner.
func AddComment(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	productIDStr := strings.TrimSpace(r.FormValue("product_id"))
	author := strings.TrimSpace(r.FormValue("author"))
	content := r.FormValue("content")

	if productIDStr == "" || author == "" {
		http.Error(w, "missing fields", http.StatusBadRequest)
		return
	}
	pid, err := strconv.ParseInt(productIDStr, 10, 64)
	if err != nil || pid <= 0 {
		http.Error(w, "invalid product_id", http.StatusBadRequest)
		return
	}

	// DB insert (secure/insecure farkı burada değil; render tarafında).
	_, err = DB.Exec(
		`INSERT INTO comments (product_id, author, content, created_at)
         VALUES (?, ?, ?, CURRENT_TIMESTAMP)`,
		pid, author, content,
	)
	if err != nil {
		http.Error(w, "insert error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Ürün detayına dön → Stored XSS demoyu orada görürsün.
	http.Redirect(w, r, fmt.Sprintf("/product-detail.html?id=%d", pid), http.StatusSeeOther)
}
