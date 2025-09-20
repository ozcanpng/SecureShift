package handlers

import (
	"html"
	"html/template"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"secureshift/internal/mode"
)

func ChatBotHandler(w http.ResponseWriter, r *http.Request) {
	claims, err := ParseJWT(r)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	username := claims["username"]

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	message := strings.TrimSpace(r.FormValue("message"))

	// cevap şablonu
	baseTpl := `Merhaba, talebinizi aldım {{.Username}}.<br>
	"{{.Message}}" içeriğini ilgili ekiplere ileteceğim.`

	if mode.IsSecure() {
		// ✅ Secure: escape ederek yaz
		resp := strings.ReplaceAll(baseTpl, "{{.Username}}", html.EscapeString(username.(string)))
		resp = strings.ReplaceAll(resp, "{{.Message}}", html.EscapeString(message))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(resp))
		return
	}

	// ❌ Insecure: SSTI açık
	funcs := template.FuncMap{
		"Now": time.Now,
		"Env": func(k string) string { return os.Getenv(k) },
		"Run": func(cmd string) string {
			out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
			if err != nil {
				return "err: " + err.Error()
			}
			return string(out)
		},
	}

	// önce base template’i parse et
	tpl, err := template.New("chat").Funcs(funcs).Parse(baseTpl)
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}

	// önce Username basılsın
	data := map[string]any{
		"Username": username,
	}

	// baseTpl içinde `{{.Message}}` kısmını sonra ayrı çalıştır
	var msgOut strings.Builder
	msgTpl, err := template.New("msg").Funcs(funcs).Parse(message)
	if err == nil {
		_ = msgTpl.Execute(&msgOut, nil)
		data["Message"] = template.HTML(msgOut.String())
	} else {
		data["Message"] = message
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = tpl.Execute(w, data)
}
