package handlers

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"secureshift/internal/mode"
)

var productsTpl = template.Must(template.ParseFiles("./web/products.html"))

type Product struct {
	ID          sql.NullInt64 `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Price       string        `json:"price"`
	ImageURL    string        `json:"imageURL"`
}

func ProductsHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")

	var (
		rows *sql.Rows
		err  error
	)

	if mode.IsSecure() {
		if q != "" {
			rows, err = DB.Query(
				`SELECT id, name, description, price, imageURL
				 FROM products
				 WHERE name LIKE ?`,
				"%"+q+"%",
			)
		} else {
			rows, err = DB.Query(`SELECT id, name, description, price, imageURL FROM products`)
		}
	} else {
		query := `SELECT id, name, description, price, imageURL FROM products`
		if q != "" {
			query += fmt.Sprintf(` WHERE name LIKE '%%%s%%'`, q)
		}
		rows, err = DB.Query(query)
	}

	if err != nil {
		log.Printf("Database error: %v", err)
		_ = productsTpl.Execute(w, map[string]any{
			"Products": []Product{},
			"Q":        q,
			"Error":    err.Error(),
		})
		return
	}
	defer rows.Close()

	var list []Product
	for rows.Next() {
		var p Product
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.Price, &p.ImageURL); err != nil {
			log.Println("scan error:", err)
			continue
		}
		list = append(list, p)
	}

	_ = productsTpl.Execute(w, map[string]any{
		"Products": list,
		"Q":        q,
	})

	log.Printf("ProductsHandler: %d ürün bulundu (query=%q)", len(list), q)
}
