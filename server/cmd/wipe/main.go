// 一次性数据清理：清空项目相关桶，保留 settings（模型/测绘 Key/单价）。
// 用法: go run ./cmd/wipe -db <jiutouniao.db 路径>
package main

import (
	"flag"
	"fmt"
	"log"

	bolt "go.etcd.io/bbolt"
)

func main() {
	dbPath := flag.String("db", "", "jiutouniao.db 路径")
	flag.Parse()
	if *dbPath == "" {
		log.Fatal("需要 -db 参数")
	}
	db, err := bolt.Open(*dbPath, 0o600, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	drop := []string{"projects", "findings", "assets", "timeline", "approvals", "evidence", "coverage", "usage", "chats", "stream", "subtasks", "asks"}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range drop {
			if b := tx.Bucket([]byte(name)); b != nil {
				if err := tx.DeleteBucket([]byte(name)); err != nil {
					return err
				}
			}
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return err
			}
		}
		// 设置桶计数确认保留
		if b := tx.Bucket([]byte("settings")); b != nil {
			fmt.Println("settings 保留条目:", b.Stats().KeyN)
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("已清空项目数据（projects/findings/assets/timeline/approvals/evidence/coverage/usage/chats/stream/subtasks/asks）")
}
