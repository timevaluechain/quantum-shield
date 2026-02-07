package main

import (
    "fmt"
    "net/http"
    "os/exec"
)

func quantumHandler(w http.ResponseWriter, r *http.Request) {
    // Memanggil mesin Kyber C yang sudah sukses lo buat
    cmd := exec.Command("./q_tunnel")
    out, _ := cmd.CombinedOutput()
    
    // Set Header agar bisa diakses browser
    w.Header().Set("Content-Type", "text/plain")
    fmt.Fprintf(w, "🛡️ QUANTUM PROTECT STATUS:\n%s", out)
}

func main() {
    // Endpoint untuk PWA melakukan handshake
    http.HandleFunc("/handshake", quantumHandler)
    
    // Endpoint untuk file static (HTML/Manifest)
    http.Handle("/", http.FileServer(http.Dir("./public")))

    fmt.Println("🚀 Quantum Protect Server Pro aktif di port 8080...")
    http.ListenAndServe(":8080", nil)
}

