package main

import (
	"log"
	"net/http"

	"github.com/TharmiganK/ballerina-scan-sarif-demo/go/internal/auth"
	"github.com/TharmiganK/ballerina-scan-sarif-demo/go/internal/documents"
	"github.com/TharmiganK/ballerina-scan-sarif-demo/go/internal/orders"
	"github.com/TharmiganK/ballerina-scan-sarif-demo/go/internal/webhooks"
)

func main() {
	mux := http.NewServeMux()
	orders.Register(mux)
	webhooks.Register(mux)
	documents.Register(mux)
	auth.Register(mux)
	log.Fatal(http.ListenAndServe(":9090", mux))
}
