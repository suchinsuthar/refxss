package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

/* ========= COLORS ========= */
const (
	green = "\033[32m"
	red   = "\033[31m"
	pink  = "\033[35m"
	reset = "\033[0m"
)

/* ========= MARKERS ========= */
const (
	prefix = "aprefix"
	suffix = "asuffix"
)

/* ========= TYPES ========= */
type Result struct {
	URL    string
	Param  string
	Chars  []string
}

type headerFlags []string

func (h *headerFlags) String() string { return "" }
func (h *headerFlags) Set(v string) error {
	*h = append(*h, v)
	return nil
}

/* ========= FLAGS ========= */
var (
	timeout     int
	concurrency int
	headers     headerFlags
)

/* ========= MAIN ========= */
func main() {
	flag.IntVar(&timeout, "t", 10, "Request timeout (seconds)")
	flag.IntVar(&concurrency, "c", 40, "Concurrency level")
	flag.Var(&headers, "H", "Custom header (repeatable)")
	flag.Parse()

	client := buildClient()

	sc := bufio.NewScanner(os.Stdin)
	input := make(chan string)
	results := make(chan Result)

	/* === WORKERS === */
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for rawURL := range input {
				cleanURL := normalizeURL(rawURL)
				params := findReflectedParams(client, cleanURL)
				for _, p := range params {
					chars := testSpecialChars(client, cleanURL, p)
					if len(chars) > 0 {
						results <- Result{
							URL:   cleanURL,
							Param: p,
							Chars: chars,
						}
					}
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	go func() {
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" {
				input <- line
			}
		}
		close(input)
	}()

	/* === GROUP RESULTS === */
	foundAny := false
	grouped := make(map[string]map[string][]string)

	for r := range results {
		foundAny = true
		if _, ok := grouped[r.URL]; !ok {
			grouped[r.URL] = make(map[string][]string)
		}
		grouped[r.URL][r.Param] = r.Chars
	}

	/* === PRINT === */
	for url, params := range grouped {
		fmt.Printf("%s[REFLECTED]%s %s\n", green, reset, url)
		for param, chars := range params {
			fmt.Printf("    %sParam:%s %s\n", pink, reset, param)
			fmt.Printf("    Unfiltered: %v\n\n", chars)
		}
	}

	if !foundAny {
		fmt.Printf("%s[-] No reflected XSS parameters found%s\n", red, reset)
	}
}

/* ========= URL NORMALIZATION ========= */
func normalizeURL(u string) string {
	replacer := strings.NewReplacer(
		`\\?`, `?`,
		`\?`, `?`,
		`\=`, `=`,
		`\&`, `&`,
	)
	return replacer.Replace(u)
}

/* ========= STEP 1: FIND REFLECTION ========= */
func findReflectedParams(client *http.Client, target string) []string {
	resp, body := doRequest(client, target)
	if resp == nil {
		return nil
	}

	if !strings.Contains(resp.Header.Get("Content-Type"), "html") {
		return nil
	}

	u, err := url.Parse(target)
	if err != nil {
		return nil
	}

	var reflected []string
	for k, v := range u.Query() {
		if len(v) == 0 {
			continue
		}

		val := v[0]

		// Check multiple representations
		if strings.Contains(body, val) ||
			strings.Contains(body, url.QueryEscape(val)) ||
			strings.Contains(body, strings.ReplaceAll(val, " ", "+")) {

			reflected = append(reflected, k)
		}
	}

	return reflected
}

/* ========= STEP 2: SPECIAL CHAR TEST ========= */
func testSpecialChars(client *http.Client, target, param string) []string {
	chars := []string{
		`"`, `'`, `<`, `>`, `$`, `|`,
		`(`, `)`, "`", ":", ";", "{", "}",
	}

	var unfiltered []string

	for _, c := range chars {
		payload := prefix + c + suffix
		if checkAppend(client, target, param, payload) {
			unfiltered = append(unfiltered, c)
		}
	}

	return unfiltered
}

/* ========= APPEND & CHECK ========= */
func checkAppend(client *http.Client, target, param, payload string) bool {
	u, err := url.Parse(target)
	if err != nil {
		return false
	}

	q := u.Query()
	q.Set(param, q.Get(param)+payload)
	u.RawQuery = q.Encode()

	_, body := doRequest(client, u.String())
	return strings.Contains(body, payload)
}

/* ========= HTTP ========= */
func doRequest(client *http.Client, target string) (*http.Response, string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return nil, ""
	}

	req.Header.Set("User-Agent", "refxss/1.0")
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	resp, err := client.Do(req)
	if err != nil || resp.Body == nil {
		return nil, ""
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, ""
	}

	return resp, string(data)
}

/* ========= CLIENT ========= */
func buildClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: (&net.Dialer{
				Timeout: time.Duration(timeout) * time.Second,
			}).DialContext,
		},
	}
}
