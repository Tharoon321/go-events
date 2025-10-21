package utils

import (
	"crypto/rand"
	"fmt"
	"net/smtp"
	"os"
)

// GenerateOTP generates a numeric OTP of n digits (cryptographically random)
func GenerateOTP(n int) string {
	bytes := make([]byte, n)
	_, err := rand.Read(bytes)
	if err != nil {
		// fallback to time-based simple OTP if rand fails (very rare)
		return fmt.Sprintf("%06d", 0)
	}
	// create numeric from bytes
	otp := make([]byte, n)
	for i := 0; i < n; i++ {
		otp[i] = '0' + (bytes[i] % 10)
	}
	return string(otp)
}

// SendMail sends a plain-text email using SMTP (Gmail example)
func SendMail(to, subject, body string) error {
	host := os.Getenv("SMTP_HOST")
	port := os.Getenv("SMTP_PORT")
	user := os.Getenv("SMTP_USER")
	pass := os.Getenv("SMTP_PASS")

	if host == "" || port == "" || user == "" || pass == "" {
		return fmt.Errorf("smtp not configured")
	}

	addr := host + ":" + port
	from := user

	// Build message
	msg := "From: " + from + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Content-Type: text/plain; charset=\"utf-8\"\r\n\r\n" +
		body + "\r\n"


	auth := smtp.PlainAuth("", user, pass, host)
	return smtp.SendMail(addr, auth, from, []string{to}, []byte(msg))
}
