package db

type (
	// RetryPolicy is a domain specific policy for how the client should perform retry attempts.
	RetryPolicy struct {
		MaxTimes int
	}

	// Data maps specific domains to specific a RetryPolicy.
	Data map[string]RetryPolicy
)

// Get gets the policy for the specified domain if it exists, otherwise
// returning a default value.
func (d Data) Get(domain string) RetryPolicy {
	rp, ok := d[domain]
	if !ok {
		return RetryPolicy{MaxTimes: 1}
	}
	return rp
}

// Set sets the policy for the specified domain.
func (d Data) Set(domain string, rp RetryPolicy) {
	d[domain] = rp
}
