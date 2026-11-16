// hashpass 生成 Web 登录口令哈希（admin_password_hash 用）：
//
//	go run ./cmd/hashpass -p '你的新口令'
//
// 把输出的 hash 值填入 config.json 的 admin_password_hash 字段，并删除 admin_password 明文行。
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
)

func main() {
	p := flag.String("p", "", "明文口令")
	flag.Parse()
	if *p == "" {
		fmt.Fprintln(os.Stderr, "用法: hashpass -p '口令'")
		os.Exit(1)
	}
	sum := sha256.Sum256([]byte("jiutouniao$v1:" + *p))
	fmt.Println(hex.EncodeToString(sum[:]))
}
