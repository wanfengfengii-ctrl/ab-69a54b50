// Command server 运行恢复密钥合成服务。
// 监听端口由环境变量 PORT 指定（默认 8080）。
package main

import (
	"log"
	"net/http"
	"os"

	"recovery/internal/server"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	addr := ":" + port
	log.Printf("recovery server listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, server.New()))
}
