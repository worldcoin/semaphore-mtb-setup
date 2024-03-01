package phase2

import (
	"testing"
)

func TestNextPowerOfTwo(t *testing.T) {
	tests := []struct {
		input    int
		expected int
	}{
		{0, 1},
		{1, 1},
		{2, 2},
		{3, 4},
		{4, 4},
		{5, 8},
		{6, 8},
		{7, 8},
		{268435456, 268435456},
	}
	for _, test := range tests {
		t.Run("NextPowerOfTwo", func(t *testing.T) {
			if NextPowerOfTwo(test.input) != test.expected {
				t.Errorf("NextPowerOfTwo(%d) != %d", test.input, test.expected)
			}
		})
	}
}
