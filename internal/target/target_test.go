package target

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Parse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "empty input",
			input:    "",
			expected: []string{""},
		},
		{
			name:     "single IP",
			input:    "192.168.1.24",
			expected: []string{"192.168.1.24"},
		},
		{
			name:     "IP range with CIDR",
			input:    "192.168.0.1/29",
			expected: []string{"192.168.0.0", "192.168.0.1", "192.168.0.2", "192.168.0.3", "192.168.0.4", "192.168.0.5", "192.168.0.6", "192.168.0.7"},
		},
		{
			name:     "short IP range with CIDR",
			input:    "10.0.0.1/30",
			expected: []string{"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"},
		},
		{
			name:     "multiple IP addresses",
			input:    "192.168.1.1;172.16.1.2;10.10.1.3",
			expected: []string{"192.168.1.1", "172.16.1.2", "10.10.1.3"},
		},
		{
			name:     "domain address",
			input:    "test.example.com",
			expected: []string{"test.example.com"},
		},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			t.Parallel()

			result := extractRange(test.input)

			assert.Equal(t, test.expected, result)
		})
	}

}
