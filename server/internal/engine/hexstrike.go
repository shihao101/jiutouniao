package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// HexStrikeBridge hexstrike-ai HTTP 工具网关桥（路由/字段与其 hexstrike_server.py 原样兼容）：
//
//	GET  /health        → {status, total_tools_count, category_stats{...}}
//	POST /api/command   {command, use_cache} → {success, stdout, stderr, return_code, execution_time}
//
// 通过该桥，九头鸟无需本机安装即可调用 hexstrike 上注册的 150+ 安全工具；
// 所有调用仍走九头鸟的审批矩阵与证据链。
type HexStrikeBridge struct {
	baseURL string
	http    *http.Client
}

func NewHexStrikeBridge(baseURL string) *HexStrikeBridge {
	return &HexStrikeBridge{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: 620 * time.Second},
	}
}

type hexHealth struct {
	Status          string `json:"status"`
	Version         string `json:"version"`
	TotalToolsCount int    `json:"total_tools_count"`
	CategoryStats   map[string]struct {
		Total     int `json:"total"`
		Available int `json:"available"`
	} `json:"category_stats"`
}

// Health 探活并返回工具统计。
func (h *HexStrikeBridge) Health(ctx context.Context) (*hexHealth, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.baseURL+"/health", nil)
	if err != nil {
		return nil, err
	}
	var out hexHealth
	if err := h.do(req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type hexCmdReq struct {
	Command  string `json:"command"`
	UseCache bool   `json:"use_cache"`
}

type hexCmdResp struct {
	Success       bool    `json:"success"`
	Stdout        string  `json:"stdout"`
	Stderr        string  `json:"stderr"`
	ReturnCode    int     `json:"return_code"`
	ExecutionTime float64 `json:"execution_time"`
	Error         string  `json:"error"`
}

// Command 经网关执行命令。
func (h *HexStrikeBridge) Command(ctx context.Context, command string) (string, error) {
	body, _ := json.Marshal(hexCmdReq{Command: command, UseCache: true})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.baseURL+"/api/command", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	var out hexCmdResp
	if err := h.do(req, &out); err != nil {
		return "", err
	}
	resp := fmt.Sprintf("success=%v return_code=%d execution_time=%.1fs\nstdout:\n%s\nstderr:\n%s",
		out.Success, out.ReturnCode, out.ExecutionTime, truncateText(out.Stdout, 4000), truncateText(out.Stderr, 1000))
	if out.Error != "" {
		resp += "\nerror: " + out.Error
	}
	return resp, nil
}

func (h *HexStrikeBridge) do(req *http.Request, out any) error {
	resp, err := h.http.Do(req)
	if err != nil {
		return fmt.Errorf("hexstrike 网关不可达: %w", err)
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("hexstrike 返回 %d: %s", resp.StatusCode, truncateText(buf.String(), 300))
	}
	return json.Unmarshal(buf.Bytes(), out)
}
