package cache

// Observer is notified when the cache is updated
type Observer interface {
	OnCacheUpdate(key string, entry *RuleSetEntry)
}
