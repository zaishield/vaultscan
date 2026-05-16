package notify

import (
	"bytes"
	"testing"
)

// pad32 left-pads ECDSA r/s scalars to 32 bytes before encoding the
// APNS JWT signature. A bug here produces invalid JWTs that APNS
// silently 401s — which the platform reports as "no push delivered"
// without surfacing the root cause. Unit-tested for the typical
// truncation scenarios.

func TestPad32_ShortInputLeftPaddedWithZeros(t *testing.T) {
	t.Parallel()
	in := []byte{0x01, 0x02}
	out := pad32(in)
	if len(out) != 32 {
		t.Fatalf("len=%d want 32", len(out))
	}
	// Leading 30 bytes must be zero; trailing 2 must equal input.
	for i := 0; i < 30; i++ {
		if out[i] != 0 {
			t.Errorf("padding byte %d non-zero: %x", i, out[i])
		}
	}
	if !bytes.Equal(out[30:], in) {
		t.Errorf("tail=%x want %x", out[30:], in)
	}
}

func TestPad32_ExactlyThirtyTwoUnchanged(t *testing.T) {
	t.Parallel()
	in := bytes.Repeat([]byte{0xAB}, 32)
	out := pad32(in)
	if !bytes.Equal(out, in) {
		t.Errorf("32-byte input mutated: got %x", out)
	}
}

func TestPad32_LongerInputReturnedUnchanged(t *testing.T) {
	t.Parallel()
	in := bytes.Repeat([]byte{0xCD}, 40)
	out := pad32(in)
	// Function returns the input as-is when it's already ≥32 bytes.
	if !bytes.Equal(out, in) {
		t.Errorf("≥32 input mutated; got %x want %x", out, in)
	}
}

func TestPad32_EmptyInput(t *testing.T) {
	t.Parallel()
	out := pad32(nil)
	if len(out) != 32 {
		t.Errorf("nil input → len=%d want 32", len(out))
	}
	for _, b := range out {
		if b != 0 {
			t.Errorf("nil input → non-zero byte %x", b)
		}
	}
}
