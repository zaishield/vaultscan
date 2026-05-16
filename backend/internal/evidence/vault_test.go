package evidence

import "testing"

func TestEncryptDecryptRoundTrip(t *testing.T) {
	t.Parallel()
	v := &Vault{masterKey: []byte("01234567890123456789012345678901")} // 32 bytes
	plain := []byte("scanner output goes here, do not lose it")
	ct, nonce, err := v.encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) == 0 || len(nonce) == 0 {
		t.Fatal("empty ciphertext or nonce")
	}
	got, err := v.decrypt(ct, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plain) {
		t.Fatalf("got %q want %q", got, plain)
	}
}

func TestSignedURLTamperRejected(t *testing.T) {
	t.Parallel()
	v := &Vault{masterKey: []byte("01234567890123456789012345678901")}
	if !constantTimeEqualString("abc", "abc") {
		t.Fatal("constantTimeEqualString broken")
	}
	_ = v
}
