package handlers

import (
	"fmt"
	"io"
	"log"
	"net/http"

	"secureshift/internal/mode"

	"github.com/lestrrat-go/libxml2/parser"
	"github.com/lestrrat-go/libxml2/types"
)

// Görüntüde kullanacağımız basit model
type AboutXML struct {
	Title   string
	Content string
}

var aboutCache = AboutXML{
	Title: "TechShop Teknoloji Mağazası",
	Content: "TechShop, en yeni teknoloji ürünlerini müşterilerine uygun fiyatlarla sunan dinamik bir e-ticaret platformudur.\n\n" +
		"Misyonumuz: Teknolojiyi herkes için ulaşılabilir ve güvenilir hale getirmek.\n" +
		"Vizyonumuz: Türkiye’nin en güvenilir teknoloji mağazası olmak ve global pazarda da kullanıcıların ilk tercihi haline gelmek.\n" +
		"Değerlerimiz: Güvenilir alışveriş, hızlı teslimat, müşteri memnuniyeti, sürekli yenilik.",
}

func AboutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// JSON olarak döndür
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"title":%q, "content":%q}`, aboutCache.Title, aboutCache.Content)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseMultipartForm(5 << 20); err != nil {
		http.Error(w, "Bad form", http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("xmlfile")
	if err != nil {
		http.Error(w, "Missing file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	xmlBytes, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Read fail", http.StatusInternalServerError)
		return
	}

	// SECURE vs INSECURE
	if mode.IsSecure() {
		p := parser.New(parser.XMLParseNoNet)
		doc, err := p.Parse(xmlBytes)
		if err != nil {
			log.Printf("Secure XML parse error: %v", err)
			http.Error(w, "Invalid XML", http.StatusBadRequest)
			return
		}
		defer doc.Free()

		root, _ := doc.DocumentElement()
		title := getChildText(root, "title")
		content := getChildText(root, "content")

		aboutCache = AboutXML{
			Title:   title,
			Content: content,
		}
	} else {
		p := parser.New(parser.XMLParseNoEnt)
		doc, err := p.Parse(xmlBytes)
		if err != nil {
			log.Printf("Insecure XML parse error: %v", err)
			http.Error(w, "Invalid XML", http.StatusBadRequest)
			return
		}
		defer doc.Free()

		root, _ := doc.DocumentElement()
		title := getChildText(root, "title")
		content := getChildText(root, "content")

		aboutCache = AboutXML{
			Title:   title,
			Content: content,
		}
	}

	http.Redirect(w, r, "/about.html", http.StatusSeeOther)
}

// Yardımcı: kök altındaki belirli tag'in text içeriğini döndür
func getChildText(root types.Node, tag string) string {
	if root == nil {
		return ""
	}
	children, err := root.ChildNodes()
	if err != nil {
		return ""
	}
	for _, c := range children {
		if c.NodeName() == tag {
			return c.TextContent()
		}
	}
	return ""
}
