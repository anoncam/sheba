/* --- LICENCE ---
* SHEBA is licenced under the GNU GPLv3
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
// testing the github bot
package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	//chroma "github.com/alecthomas/chroma"
	virustotal "github.com/dutchcoders/go-virustotal"
	"github.com/gorilla/mux"
	"github.com/peterbourgon/diskv"
	md "github.com/shurcooL/github_flavored_markdown"
	"html/template"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

/* --- config --- */
const (
	/* --- url settings ---  */
  formVal      = "p"
	siteName     = "SHEBASH" // 7 char long title
	minPasteSize = 16
	maxPasteSize = 1024 * 1024 * 1024                                                // 1024 MB
	urlLength    = 8                                                                // charlength of the url
	urlCharset   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" // available characters the url can use

	/* --- database settings --- */
	basePath  = "bashes"          // dir that the db is located in
	cacheSize = 128 * 1024 * 1024 // 128 MB

	/* --- server settings --- */
	useSSL      = true
	httpsPort   = 443                  // ssl port
	sslCertPath = "cert/fullchain.pem" // ssl cert
	sslKeyPath  = "cert/privkey.pem"   // ssl priv key
	apiKeyPath  = "cert/api.txt"       // postal api key
	vtKeyPath   = "cert/vt.txt"      // virustotal api key
	httpPort    = 80 // http port
	bindAddress = "" // bind address
)

var apiKey string

var vtKey string

var usageText = struct {
	index, temp, scan, md string
}{
	index: `
    Custom urls are also available.

    ( EXAMPLE: sheba.sh/hootie/ )

    // TODO: Incorperate Lexers
    `,
	temp: `
    /temp/ is a temporary paste subdir. For burner notes.  Once accessed, the file or, if custom, the directory is removed.
		This results in a 404 HTTP error when attempting to view the URL a second time.

		i.e. hit refresh ;)
    `,
	scan: `
    /scan/ will scan uploaded files for viruses using VirusTotal. The link
    to the VirusTotal scan results will be returned.
    `,
	md: `
    /md/ is a Github flavored markdown parser. Files uploaded here will be
    rendered in html using the same syntax as Github's markdown.
    `,
}

/* fork of compost, by sir oss */

const standardUsageText = `
<!doctype html>
<html>
<head>
<title>{{.BaseURL}}{{.SubDir}} - command line var bin</title>

</head>
<body>
<pre>
{{.BaseURL}}(1)                    {{.Name}}                    {{.BaseURL}}(1)

NAME
    {{.BaseURL}}{{.SubDir}} - command line var bin

EXPLORE
    Shell output:
    &lt;command&gt; | curl {{.BaseURL}}{{.SubDir}}/ -T-

    Files:
    curl {{.BaseURL}}{{.SubDir}}/ -T &lt;file&gt;

DESCRIPTION
    A simple, no bullshit command line pastebin. Pastes are created using HTTP
    POST requests. The url is then returned and can be accessed from there.
    {{.DirUsage}}

EXAMPLE
    $ echo '{{.Name}} does not frequent dal.net' | curl {{.BaseURL}}{{.SubDir}}/ -T-
      {{.BaseURL}}{{.SubDir}}/TEST
    $ curl {{.BaseURL}}{{.SubDir}}/TEST
      {{.Name}} does not frequent dal.net

UNIQUE SUBDIRS
    <a href="http://{{.BaseURL}}/static/">{{.BaseURL}}/static/</a> is a static file server.
    <a href="http://{{.BaseURL}}/temp/">{{.BaseURL}}/temp/</a> is for burner pastes.
    <a href="http://{{.BaseURL}}/md/">{{.BaseURL}}/md/</a> render md file to html for webviewing.
		<a href="http://{{.BaseURL}}/scan/">{{.BaseURL}}/scan/</a> Use virus total api to return a report of a file you tee off to scan.

SEE ALSO
    {{.Name}} brought to you for free and open source at <a href="https://github.com/anoncam/sheba">https://github.com/anoncam/sheba/</a>

DONATE
XMR 4647Wo9XKjdEJ515Ch4N9S6tmEgMfiJ5UUEMAZTFw2jr5aWRANsQq5WgT1hVNfAiQAhpxwpYN1LBEdXKSA3aSLeJDJcZRGn
BTC 1C22b9YGktv5JRhuU6n7424oQ71zkLRsyg
LTC LQKngTfNM9NBBiFaranqxEcNbPBKtys5BJ
DASH XhCLx3UPZaF1ydjERtfGgkW2A1nkAXEEyC
      </pre>
</body>
</html>
`

var reg, _ = regexp.Compile("(\\.[^.]+)$")

// Logic Flow and Error Responses
type (
	pasteTooLarge struct{}
	pasteTooSmall struct{}
	pasteNotFound struct{}
	pasteExists   struct{}
)

func (e pasteTooLarge) Error() string {
	return fmt.Sprintf("paste too large (maximum size %d bytes)", maxPasteSize)
}
func (e pasteTooSmall) Error() string { return "paste too small" }
func (e pasteNotFound) Error() string { return "404 not found" }
func (e pasteExists) Error() string   { return "file exists" }

func newID() string {
	urlID := make([]byte, urlLength)
	for i := range urlID {
		urlID[i] = urlCharset[rand.Intn(len(urlCharset))]
	}
	return string(urlID)
}

func flatTransform(s string) []string {
	return []string{}
}

type handler struct {
	disk *diskv.Diskv
}

func readPaste(h *diskv.Diskv, key string) (paste string, err error) {
	var rawPaste []byte
	rawPaste, err = h.Read(key) //key is the paste name
	if err != nil {
		err = pasteNotFound{}
		return
	}
	paste = string(rawPaste)
	return
}

func deletePaste(h *diskv.Diskv, key string) (err error) {
	_, err = h.Read(key) //key is the paste name
	if err != nil {
		err = pasteNotFound{}
		return
	}
	h.Erase(key)
	return
}

func writePaste(h *diskv.Diskv, name string, data []byte) (key string, err error) {
	if len(data) > maxPasteSize {
		err = pasteTooLarge{}
		return
	} else if len(data) < minPasteSize {
		err = pasteTooSmall{}
		return
	}
	name = reg.FindString(name)
	key = newID() + name
	for h.Has(key) {
		key = newID() + name // loop that shit til unique id
	}
	h.Write(key, data)
	return
}

func writeEmail(h *diskv.Diskv, timestamp, date, to, from, subject, body_html, body_plain, atachments string) {
	var body string
	if body_html != "" {
		body = body_html
	} else {
		body = body_plain
	}
	h.Write(fmt.Sprintf("%s_%s.html", timestamp, subject), []byte(fmt.Sprintf("<pre>%s\nfrom: %s\nto: %s\nsubject: %s\n<hr>\n%s\n</pre>", date, from, to, subject, body)))
}

func craftMail(to, from, subject, body string) []byte {
	data := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("To: %s\r\nFrom: %s@compst.io\r\nSubject: %s\r\n\r\n%s", to, from, subject, body)))
	return []byte(fmt.Sprintf("{\"mail_from\":\"%s@compst.io\",\"rcpt_to\":[\"%s\"],\"data\":\"%s\"}", from, to, data))
}

func sendEmail(to, subject, body string) (key string, err error) {
	key = newID()
	b := bytes.NewBuffer(craftMail(to, key, subject, body))
	req, err := http.NewRequest("POST", "https://postal.compst.io/api/v1/send/raw", b)
	req.Header.Set("X-Server-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	defer resp.Body.Close()
	ba, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(ba))
	return
}

func Highlight(code string, lexer string, key string) (string, error) {
	cmd := exec.Command("pygmentize", "-l"+lexer, "-fhtml", "-O encoding=utf-8,full,style=borland,linenos=table,title="+key) //construct and exec html lexar
	cmd.Stdin = strings.NewReader(code)
	var out bytes.Buffer
	cmd.Stdout = &out
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	return out.String(), err
}

func (h *handler) scan(w http.ResponseWriter, req *http.Request) {
	j := diskv.New(diskv.Options{
		BasePath:     fmt.Sprintf("%s/_scan", basePath),
		Transform:    flatTransform,
		CacheSizeMax: cacheSize,
	})
	body := req.FormValue(formVal)
	key := newID()
	j.Write(key, []byte(body))
	filename := fmt.Sprintf("%s/_scan/%s", basePath, key)

	vt, err := virustotal.NewVirusTotal(vtKey)
	if err != nil {
		http.Error(w, err.Error(), 500)
	}

	reader, _ := os.Open(filename)
	result, err := vt.Scan(filename, reader)
	if err != nil {
		http.Error(w, err.Error(), 500)
	}
	w.Write([]byte(fmt.Sprintf("%v\n", result.Permalink)))
}

func (h *handler) getCompost(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	j := diskv.New(diskv.Options{
		BasePath:     fmt.Sprintf("%s/_%s", basePath, vars["dir"]),
		Transform:    flatTransform,
		CacheSizeMax: cacheSize,
	})

	if useSSL {
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains") //ssl lab bullshit
	}
	if vars["file"] != "" {
		paste, err := readPaste(j, vars["file"])
		if err != nil {
			if _, ok := err.(pasteNotFound); ok {
				http.Error(w, "not found", http.StatusNotFound)

			} else {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			log.Printf("[READ ] _%s/%s (error: %s)\n", vars["dir"], vars["file"], err.Error())
			return
		}
		log.Printf("[READ ] _%s/%s\n", vars["dir"], vars["file"])

		var finPaste string
		if vars["dir"] == "md" {
			finPaste = string(md.Markdown([]byte(paste)))
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		} else if req.URL.RawQuery != "" {
			finPaste, err = Highlight(paste, req.URL.RawQuery, vars["file"])
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if err != nil {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				finPaste = paste
			}
		} else {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			finPaste = paste
		}
		fmt.Fprintf(w, "%s", finPaste)
		if vars["dir"] == "temp" {
			deletePaste(j, vars["file"])
		}

		return
	}
}

func (h *handler) put(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)

	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		fmt.Fprint(w, "an error occurred")
		return
	}

	dir := vars["dir"]
	j := diskv.New(diskv.Options{
		BasePath:     fmt.Sprintf("%s/_%s", basePath, dir),
		Transform:    flatTransform,
		CacheSizeMax: cacheSize,
	})

	key, err := writePaste(j, vars["file"], body)
	if err != nil {
		switch err.(type) {
		case pasteTooLarge, pasteTooSmall:
			http.Error(w, err.Error(), http.StatusNotAcceptable)
		default:
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		log.Printf("[WRITE] _%s/%s (error: %s)\n", vars["dir"], vars["file"], err.Error())
		return
	}

	log.Printf("[WRITE] _%s/%s\n", vars["dir"], key)

	if dir != "" {
		dir = dir + "/"
	}
	var scheme string
	if req.TLS != nil {
		scheme = "https://"
	} else {
		scheme = "http://"
	}
	fmt.Fprintf(w, "%s%s/%s%s\n", scheme, req.Host, dir, key)
	return
}

func (h *handler) usage(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl, err := template.New("usage").Parse(standardUsageText)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	trailingSlash := (map[bool]string{true: "/", false: ""})[vars["dir"] != ""]
	subDir := trailingSlash + vars["dir"]
	baseURL := req.Host
	var dirUsage string
	switch vars["dir"] {
	case "temp":
		dirUsage = usageText.temp
	case "scan":
		dirUsage = usageText.scan
	case "md":
		dirUsage = usageText.md
	default:
		dirUsage = usageText.index
	}
	data := struct {
		BaseURL  string
		DirUsage string
		SubDir   string
		Name     string
	}{baseURL, dirUsage, subDir, siteName}
	_ = tmpl.Execute(w, data)
}

func newHandler() http.Handler {
	h := handler{}
	/* add config for static subdir */
	r := mux.NewRouter().StrictSlash(false)

	r.HandleFunc("/{dir}/", h.usage).Methods("GET")
	r.PathPrefix("/mail/").Handler(http.StripPrefix("/mail/", http.FileServer(http.Dir(fmt.Sprintf("%s/_mail", basePath))))).Methods("GET")
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir(fmt.Sprintf("%s/_static", basePath))))).Methods("GET")
	r.PathPrefix("/.well-known/").Handler(http.StripPrefix("/.well-known/", http.FileServer(http.Dir(".well-known")))) // letsencrypt
	r.HandleFunc("/{dir}/{file}", h.getCompost).Methods("GET")
	r.HandleFunc("/{file}", h.getCompost).Methods("GET")
	r.HandleFunc("/", h.usage).Methods("GET")

		r.HandleFunc("/scan/", h.scan).Methods("POST")
		r.HandleFunc("/scan/", h.scan).Methods("POST")

	r.HandleFunc("/{dir}/{file}", h.put).Methods("PUT")
	r.HandleFunc("/{dir}/", h.put).Methods("PUT")
	r.HandleFunc("/{file}", h.put).Methods("PUT")
	r.HandleFunc("/", h.put).Methods("PUT")
	return r
}

func main() {
	rand.Seed(time.Now().UTC().UnixNano())
	api, _ := ioutil.ReadFile(apiKeyPath)
	apiKey = strings.Replace(string(api), "\n", "", -1)
	vt, _ := ioutil.ReadFile(vtKeyPath)
	vtKey = strings.Replace(string(vt), "\n", "", -1)
	http.Handle("/", newHandler())
	if useSSL {
		httpsAddr := fmt.Sprintf("%s:%d", bindAddress, httpsPort)
		go http.ListenAndServeTLS(httpsAddr, sslCertPath, sslKeyPath, nil) //goroutine for your securitayyyyyy
	}
	httpAddr := fmt.Sprintf("%s:%d", bindAddress, httpPort)
	fmt.Print(http.ListenAndServe(httpAddr, nil))
}
