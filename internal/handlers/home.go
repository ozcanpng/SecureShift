package handlers

import (
	"net/http"
)

func noCache(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

// "/" -> web/index.html
func Home(w http.ResponseWriter, r *http.Request) {
	noCache(w)
	http.ServeFile(w, r, "./web/index.html")
}
