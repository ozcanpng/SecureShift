package mode

import "sync"

var (
	mu     sync.RWMutex
	secure = false
)

func IsSecure() bool {
	mu.RLock()
	defer mu.RUnlock()
	return secure
}

func SetMode(m string) {
	mu.Lock()
	defer mu.Unlock()
	secure = (m == "secure")
}

func GetMode() string {
	if IsSecure() {
		return "secure"
	}
	return "insecure"
}
