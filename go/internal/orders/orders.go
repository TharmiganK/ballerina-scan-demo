package orders

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
)

type Status string

const (
	Pending Status = "PENDING"
	Paid    Status = "PAID"
	Shipped Status = "SHIPPED"
)

type Item struct {
	SKU      string `json:"sku"`
	Quantity int    `json:"quantity"`
}

type Order struct {
	ID         string `json:"id"`
	CustomerID string `json:"customerId"`
	Items      []Item `json:"items"`
	Status     Status `json:"status"`
}

type store struct {
	mu     sync.Mutex
	orders map[string]Order
}

var orders = &store{orders: map[string]Order{}}

func Register(mux *http.ServeMux) {
	mux.Handle("GET /orders", withCors(http.HandlerFunc(listOrders)))
	mux.Handle("GET /orders/{id}", withCors(http.HandlerFunc(getOrder)))
	mux.Handle("POST /orders", withCors(http.HandlerFunc(createOrder)))
	mux.Handle("GET /orders/checkout/{returnUrl}", withCors(http.HandlerFunc(checkout)))
	// Vulnerable: ballerina/http:1 (CWE-352) - the legacy sync endpoint answers every HTTP method, including unsafe ones.
	mux.HandleFunc("/legacy/sync", legacySync)
}

// Vulnerable: ballerina/http:2 (CWE-942) - any origin may call the API with the user's credentials.
func withCors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		next.ServeHTTP(w, r)
	})
}

func listOrders(w http.ResponseWriter, _ *http.Request) {
	orders.mu.Lock()
	defer orders.mu.Unlock()
	all := make([]Order, 0, len(orders.orders))
	for _, o := range orders.orders {
		all = append(all, o)
	}
	writeJSON(w, http.StatusOK, all)
}

func getOrder(w http.ResponseWriter, r *http.Request) {
	orders.mu.Lock()
	defer orders.mu.Unlock()
	o, ok := orders.orders[r.PathValue("id")]
	if !ok {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, o)
}

func createOrder(w http.ResponseWriter, r *http.Request) {
	var o Order
	if err := json.NewDecoder(r.Body).Decode(&o); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	o.ID = newID()
	o.Status = Pending
	orders.mu.Lock()
	orders.orders[o.ID] = o
	orders.mu.Unlock()
	writeJSON(w, http.StatusCreated, o)
}

// Vulnerable: ballerina/http:4 (CWE-601) - the client chooses where the browser is sent after checkout.
func checkout(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, r.PathValue("returnUrl"), http.StatusTemporaryRedirect)
}

func legacySync(w http.ResponseWriter, _ *http.Request) {
	_, _ = w.Write([]byte("synced"))
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
