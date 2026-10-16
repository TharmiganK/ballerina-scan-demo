package webhooks

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/smtp"
	"os"
)

const subscriberBaseURL = "http://subscribers.internal.example.com"

type Event struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

func Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /webhooks/{target}", relay)
}

func relay(w http.ResponseWriter, r *http.Request) {
	var event Event
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	target := r.PathValue("target")
	apiKey := os.Getenv("RELAY_API_KEY")
	// Vulnerable: ballerina/log:1 (CWE-532) - the API key is written to the log.
	log.Printf("Relaying %s to %s with key %s", event.Type, target, apiKey)

	// Vulnerable: ballerina/http:3 (CWE-918) - the caller picks the internal path the relay calls (SSRF).
	resp, err := http.Get(subscriberBaseURL + "/hooks/" + target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.Copy(w, resp.Body)
}

// SendFailureAlert emails the operators when a delivery fails.
func SendFailureAlert(target, reason string) error {
	host := os.Getenv("SMTP_HOST")
	// Vulnerable: ballerina/email:1 (CWE-297) - the SMTP server certificate is not verified.
	// Go has no hostname-only switch; InsecureSkipVerify also skips chain validation.
	conn, err := tls.Dial("tcp", host+":465", &tls.Config{ServerName: host, InsecureSkipVerify: true})
	if err != nil {
		return err
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Auth(smtp.PlainAuth("", os.Getenv("SMTP_USER"), os.Getenv("SMTP_PASSWORD"), host)); err != nil {
		return err
	}
	recipient := "ops@example.com"
	if err := c.Mail(os.Getenv("SMTP_USER")); err != nil {
		return err
	}
	if err := c.Rcpt(recipient); err != nil {
		return err
	}
	wc, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(wc, "Subject: Webhook delivery to %s failed\r\n\r\n%s", target, reason); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return c.Quit()
}
