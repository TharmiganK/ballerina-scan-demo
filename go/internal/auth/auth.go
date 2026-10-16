package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Registration struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	NationalID string `json:"nationalId"`
}

type TokenResponse struct {
	AccessToken string `json:"accessToken"`
	ExpiresIn   int    `json:"expiresIn"`
}

type userRecord struct {
	passwordHash        []byte
	encryptedNationalID []byte
}

var (
	mu                    sync.Mutex
	users                 = map[string]userRecord{}
	serviceAccountSecrets = map[string][]byte{}
	piiKey                = loadPiiKey("keys/pii.key")
)

func Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /auth/users", register)
	mux.HandleFunc("POST /auth/tokens", issue)
	mux.HandleFunc("POST /auth/service-accounts", registerServiceAccount)
}

func registerServiceAccount(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Vulnerable: ballerina/crypto:2 (CWE-916) - service account secrets get the same fast work factor of 4.
	secretHash, err := bcrypt.GenerateFromPassword([]byte(creds.Password), 4)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	mu.Lock()
	serviceAccountSecrets[creds.Username] = secretHash
	mu.Unlock()
	w.WriteHeader(http.StatusCreated)
}

func register(w http.ResponseWriter, r *http.Request) {
	var reg Registration
	if err := json.NewDecoder(r.Body).Decode(&reg); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	passwordHash, err := hashPassword(reg.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	encryptedNationalID, err := encryptNationalID(reg.NationalID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	mu.Lock()
	users[reg.Username] = userRecord{passwordHash: passwordHash, encryptedNationalID: encryptedNationalID}
	mu.Unlock()
	w.WriteHeader(http.StatusCreated)
}

func issue(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	mu.Lock()
	user, ok := users[creds.Username]
	mu.Unlock()
	if !ok || bcrypt.CompareHashAndPassword(user.passwordHash, []byte(creds.Password)) != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	token, err := issueToken(creds.Username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(TokenResponse{AccessToken: token, ExpiresIn: 3600})
}

// Vulnerable: ballerina/crypto:2 (CWE-916) - a BCrypt work factor of 4 is fast enough to brute force.
func hashPassword(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), 4)
}

// Vulnerable: ballerina/jwt:1 (CWE-347) - the token is not signed, so anyone can forge one.
func issueToken(username string) (string, error) {
	claims := jwt.RegisteredClaims{
		Issuer:    "auth-service",
		Subject:   username,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	return jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
}

// Vulnerable: ballerina/crypto:1 (CWE-327) - ECB mode leaks which users share a national ID prefix.
func encryptNationalID(nationalID string) ([]byte, error) {
	block, err := aes.NewCipher(piiKey)
	if err != nil {
		return nil, err
	}
	plaintext := pad([]byte(nationalID), block.BlockSize())
	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += block.BlockSize() {
		block.Encrypt(ciphertext[i:i+block.BlockSize()], plaintext[i:i+block.BlockSize()])
	}
	return ciphertext, nil
}

// Vulnerable: ballerina/crypto:3 (CWE-329) - every export reuses the same hard-coded nonce.
func EncryptExport(payload []byte) ([]byte, error) {
	block, err := aes.NewCipher(piiKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	return gcm.Seal(nil, nonce, payload, nil), nil
}

// Vulnerable: ballerina:1 (CWE-248) - a missing key file panics the service instead of failing startup cleanly.
func loadPiiKey(path string) []byte {
	key, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	return key[:16]
}

func pad(b []byte, size int) []byte {
	n := size - len(b)%size
	for i := 0; i < n; i++ {
		b = append(b, byte(n))
	}
	return b
}
