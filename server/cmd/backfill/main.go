package main

import (
	"fmt"
	"os"

	"jiutouniao/internal/store"
)

func main() {
	st, err := store.Open("/tmp/v66-backfill")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer st.Close()
	ps, _ := st.ListProjects()
	n := 0
	for _, p := range ps {
		as, _ := st.ListAssets(p.ID)
		for _, a := range as {
			if a.EffectiveScope() == "unknown" {
				a.ScopeStatus = "in_scope"
				a.ScopeEvidence = "历史项目回放补录：原授权清单成员（v6.1.0 上线前登记）"
				_ = st.UpdateAsset(a)
				n++
			}
		}
	}
	fmt.Println("回填资产:", n)
}
