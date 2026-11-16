// 一次性运维工具：按项目 ID 选择性删除测试项目（区别于 cmd/wipe 的全量清空）。
// 用法: go run ./cmd/cleanup-projects -db <jiutouniao.db> -ids JT-XXX,JT-YYY
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"strings"

	bolt "go.etcd.io/bbolt"
)

func main() {
	dbPath := flag.String("db", "", "")
	idsFlag := flag.String("ids", "", "")
	flag.Parse()
	targets := map[string]bool{}
	for _, id := range strings.Split(*idsFlag, ",") {
		if id = strings.TrimSpace(id); id != "" {
			targets[id] = true
		}
	}
	db, err := bolt.Open(*dbPath, 0o600, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// 记录型桶：值内 project_id 命中即删
	recordBuckets := []string{"findings", "assets", "timeline", "approvals", "evidence",
		"coverage", "usage", "chats", "stream", "subtasks", "asks", "facts", "loot"}
	total := map[string]int{}
	err = db.Update(func(tx *bolt.Tx) error {
		// projects 桶：key 即项目 ID
		if b := tx.Bucket([]byte("projects")); b != nil {
			for id := range targets {
				if b.Get([]byte(id)) != nil {
					if err := b.Delete([]byte(id)); err != nil {
						return err
					}
					total["projects"]++
				}
			}
		}
		for _, name := range recordBuckets {
			b := tx.Bucket([]byte(name))
			if b == nil {
				continue
			}
			type kv struct{ k, v []byte }
			var toDelete []kv
			c := b.Cursor()
			for k, v := c.First(); k != nil; k, v = c.Next() {
				var m map[string]any
				if json.Unmarshal(v, &m) == nil {
					if pid, ok := m["project_id"].(string); ok && targets[pid] {
						toDelete = append(toDelete, kv{k, v})
					}
				}
			}
			for _, kv := range toDelete {
				if err := b.Delete(kv.k); err != nil {
					return err
				}
				total[name]++
			}
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	for _, name := range append([]string{"projects"}, recordBuckets...) {
		if total[name] > 0 {
			fmt.Printf("  %-10s 删除 %d 条\n", name, total[name])
		}
	}
	fmt.Println("清理完成")
}
