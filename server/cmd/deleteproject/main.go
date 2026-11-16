// 一次性选择性删除：按项目 ID 清空其全部相关数据（区别于 wipe 的全清）。
// 用法: go run ./cmd/deleteproject -db <jiutouniao.db> -id <JT-XXXX> [-id <JT-YYYY>...]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"strings"

	bolt "go.etcd.io/bbolt"
)

var buckets = []string{"projects", "findings", "assets", "timeline", "approvals",
	"evidence", "coverage", "usage", "chats", "stream", "subtasks", "asks"}

type projRef struct {
	ProjectID string `json:"project_id"`
}

func main() {
	dbPath := flag.String("db", "", "")
	ids := flag.String("id", "", "")
	flag.Parse()
	if *dbPath == "" || *ids == "" {
		log.Fatal("需要 -db 与 -id（可多个，逗号分隔）")
	}
	target := map[string]bool{}
	for _, id := range strings.Split(*ids, ",") {
		if id = strings.TrimSpace(id); id != "" {
			target[id] = true
		}
	}
	db, err := bolt.Open(*dbPath, 0o600, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	total := 0
	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range buckets {
			b := tx.Bucket([]byte(name))
			if b == nil {
				continue
			}
			var del [][]byte
			c := b.Cursor()
			for k, v := c.First(); k != nil; k, v = c.Next() {
				match := false
				if target[string(k)] {
					match = true // projects/usage/chats 等以 projectID 为键的桶
				} else {
					var pr projRef
					if err := json.Unmarshal(v, &pr); err == nil && pr.ProjectID != "" && target[pr.ProjectID] {
						match = true
					}
				}
				if match {
					del = append(del, append([]byte{}, k...))
				}
			}
			for _, k := range del {
				if err := b.Delete(k); err != nil {
					return err
				}
				total++
			}
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("已删除 %d 条记录（目标项目: %s）\n", total, strings.Join(keys(target), ", "))
}

func keys(m map[string]bool) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	return out
}
