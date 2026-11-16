// Package events 提供按项目订阅/发布的事件总线，供 WebSocket 推送实时执行流。
package events

import (
	"encoding/json"
	"sync"
)

// Bus 每个项目一个订阅组。
type Bus struct {
	mu   sync.RWMutex
	subs map[string]map[chan []byte]struct{}
}

func NewBus() *Bus {
	return &Bus{subs: map[string]map[chan []byte]struct{}{}}
}

// Subscribe 返回该项目的事件通道。
func (b *Bus) Subscribe(projectID string) chan []byte {
	ch := make(chan []byte, 512)
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.subs[projectID] == nil {
		b.subs[projectID] = map[chan []byte]struct{}{}
	}
	b.subs[projectID][ch] = struct{}{}
	return ch
}

func (b *Bus) Unsubscribe(projectID string, ch chan []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if m, ok := b.subs[projectID]; ok {
		delete(m, ch)
		if len(m) == 0 {
			delete(b.subs, projectID)
		}
	}
}

// Publish 广播事件；type 为事件类型（log/stage/approval/finding/kill/project）。
// 推送前对载荷做去 AI 化清洗（剥离 pictograph emoji，保留印刷符号）。
func (b *Bus) Publish(projectID, typ string, data any) {
	data = SanitizeText(data)
	payload, err := json.Marshal(map[string]any{"type": typ, "data": data})
	if err != nil {
		return
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	for ch := range b.subs[projectID] {
		select {
		case ch <- payload:
		default: // 慢消费者丢弃，避免阻塞引擎
		}
	}
}
