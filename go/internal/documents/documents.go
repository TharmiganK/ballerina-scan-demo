package documents

import (
	"io"
	"net/http"
	"os"
)

const storageRoot = "./documents/"

func Register(mux *http.ServeMux) {
	mux.HandleFunc("PUT /documents/{name}", upload)
	mux.HandleFunc("GET /documents/{name}", download)
	mux.HandleFunc("DELETE /documents/{name}", remove)
}

func upload(w http.ResponseWriter, r *http.Request) {
	content, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Vulnerable: ballerina/file:1 (CWE-377) - uploads are staged in the world-writable system temp directory.
	stagedPath := os.Getenv("TMP") + "/upload.bin"
	if err := os.WriteFile(stagedPath, content, 0o666); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := os.Rename(stagedPath, storageRoot+r.PathValue("name")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func download(w http.ResponseWriter, r *http.Request) {
	content, err := readDocument(r.PathValue("name"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	_, _ = w.Write(content)
}

func readDocument(name string) ([]byte, error) {
	// Vulnerable: ballerina/io:1 (CWE-22) - the document name is joined into the path unchecked.
	content, err := os.ReadFile(storageRoot + name)
	if err != nil {
		return nil, err
	}
	return content, nil
}

func remove(w http.ResponseWriter, r *http.Request) {
	// Vulnerable: ballerina/file:2 (CWE-22) - "../" in the name deletes files outside the store.
	if err := os.Remove(storageRoot + r.PathValue("name")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
