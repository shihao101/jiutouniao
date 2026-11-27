// 只读工具：从九头鸟 bbolt 库提取 usage 分账与项目元数据，用于 token 消耗分析。
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

type UsageRecord struct {
	ProjectID   string           `json:"project_id"`
	TotalTokens int64            `json:"total_tokens"`
	InTokens    int64            `json:"in_tokens"`
	OutTokens   int64            `json:"out_tokens"`
	ByStage     map[string]int64 `json:"by_stage"`
	Calls       int              `json:"calls"`
	UpdatedAt   time.Time        `json:"updated_at"`
}

type Project struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

func main() {
	dbPath := os.Args[1]
	db, err := bolt.Open(dbPath, 0o400, &bolt.Options{Timeout: 5 * time.Second, ReadOnly: true})
	if err != nil {
		fmt.Fprintf(os.Stderr, "open: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	type row struct {
		ID      string
		Name    string
		Status  string
		Created string
		Rec     UsageRecord
	}
	var rows []row

	err = db.View(func(tx *bolt.Tx) error {
		pb := tx.Bucket([]byte("projects"))
		ub := tx.Bucket([]byte("usage"))
		if pb == nil {
			return fmt.Errorf("no projects bucket")
		}
		pb.ForEach(func(k, v []byte) error {
			var p Project
			if json.Unmarshal(v, &p) == nil {
				r := row{ID: p.ID, Name: p.Name, Status: p.Status, Created: p.CreatedAt.Format("2006-01-02")}
				if u := ub.Get([]byte(p.ID)); u != nil {
					json.Unmarshal(u, &r.Rec)
				}
				rows = append(rows, r)
			}
			return nil
		})
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "view: %v\n", err)
		os.Exit(1)
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].Created > rows[j].Created })
	fmt.Println("id\tcreated\tstatus\tcalls\tin_k\tout_k\ttotal_k\tname")
	var tIn, tOut int64
	var tCalls int
	for _, r := range rows {
		fmt.Printf("%s\t%s\t%s\t%d\t%.1f\t%.1f\t%.1f\t%s\n", r.ID, r.Created, r.Status, r.Rec.Calls,
			float64(r.Rec.InTokens)/1000, float64(r.Rec.OutTokens)/1000, float64(r.Rec.TotalTokens)/1000, r.Name)
		tIn += r.Rec.InTokens
		tOut += r.Rec.OutTokens
		tCalls += r.Rec.Calls
	}
	fmt.Printf("TOTAL\t\t\t%d\t%.1f\t%.1f\t%.1f\t\n", tCalls, float64(tIn)/1000, float64(tOut)/1000, float64(tIn+tOut)/1000)
	// 按阶段聚合
	stageAgg := map[string]int64{}
	var stageCnt int
	fmt.Println("\n=== PER-PROJECT BY_STAGE ===")
	for _, r := range rows {
		if len(r.Rec.ByStage) == 0 {
			continue
		}
		stageCnt++
		keys := make([]string, 0, len(r.Rec.ByStage))
		for k := range r.Rec.ByStage {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Printf("%s:", r.ID)
		for _, k := range keys {
			fmt.Printf(" %s=%.1fk", k, float64(r.Rec.ByStage[k])/1000)
			stageAgg[k] += r.Rec.ByStage[k]
		}
		fmt.Println()
	}

	fmt.Println("\n=== STAGE AGGREGATE (all projects) ===")
	keys := make([]string, 0, len(stageAgg))
	for k := range stageAgg {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return stageAgg[keys[i]] > stageAgg[keys[j]] })
	var gTot int64
	for _, k := range keys {
		gTot += stageAgg[k]
	}
	for _, k := range keys {
		fmt.Printf("%s\t%.1fk\t%.1f%%\n", k, float64(stageAgg[k])/1000, 100*float64(stageAgg[k])/float64(gTot))
	}
	fmt.Printf("GRAND TOTAL\t%.1fk\n", float64(gTot)/1000)
}
