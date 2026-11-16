// jt46mon-reader: 只读提取指定 bucket 前缀的键值（避免全库 49k 文件导出）
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	bolt "go.etcd.io/bbolt"
)

func main() {
	dbPath := os.Args[1]
	outDir := os.Args[2]
	prefix := os.Args[3] // bucket 前缀，如 projects__JT-46A865D51C / stream__JT-46A865D51C
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		panic(err)
	}
	db, err := bolt.Open(dbPath, 0o400, &bolt.Options{ReadOnly: true, Timeout: 0})
	if err != nil {
		fmt.Fprintln(os.Stderr, "open err:", err)
		os.Exit(1)
	}
	defer db.Close()
	var files int
	err = db.View(func(tx *bolt.Tx) error {
		return tx.ForEach(func(name []byte, b *bolt.Bucket) error {
			bucket := string(name)
			return b.ForEach(func(k, v []byte) error {
				full := bucket + "__" + string(k)
				if !strings.HasPrefix(full, prefix) {
					return nil
				}
				key := sanitize(string(k))
				fpath := filepath.Join(outDir, fmt.Sprintf("%s__%s.bin", bucket, key))
				_ = os.WriteFile(fpath, v, 0o644)
				files++
				return nil
			})
		})
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "err:", err)
	}
	fmt.Println("dumped", files, "values for prefix", prefix)
}

func sanitize(s string) string {
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, " ", "_")
	if len(s) > 120 {
		s = s[:120]
	}
	if s == "" {
		s = "_empty"
	}
	return s
}
