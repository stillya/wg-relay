package timestamp

import "testing"

func TestMonoNow(t *testing.T) {
	first, err := MonoNow()
	if err != nil {
		t.Fatalf("MonoNow failed: %v", err)
	}
	second, err := MonoNow()
	if err != nil {
		t.Fatalf("MonoNow failed: %v", err)
	}

	if first == 0 {
		t.Error("Expected non-zero timestamp")
	}
	if second < first {
		t.Errorf("Expected non-decreasing timestamps, got %d then %d", first, second)
	}
}
