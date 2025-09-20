package main

import (
	"database/sql"
	"log"
	stdhttp "net/http"
	"os"

	"secureshift/internal/handlers"
	apphttp "secureshift/internal/http"
	"secureshift/internal/mode"

	"github.com/joho/godotenv"

	_ "modernc.org/sqlite"
)

func main() {
	_ = godotenv.Load()

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	// MODE: secure/insecure (env: MODE=secure | MODE=insecure)
	mode.SetMode(os.Getenv("MODE"))

	// SQLite'e bağlan
	db, err := sql.Open("sqlite", "./data/secureshift.db")
	if err != nil {
		log.Fatal("DB open error:", err)
	}
	if err := db.Ping(); err != nil {
		log.Fatal("DB ping error:", err)
	}
	defer db.Close()
	handlers.DB = db

	// Router
	r := apphttp.NewRouter()

	log.Printf("SecureShift listening on http://localhost:%s  (mode=%s)", port, mode.GetMode())
	log.Fatal(stdhttp.ListenAndServe(":"+port, r))
}
