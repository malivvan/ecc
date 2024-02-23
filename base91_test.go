package ecc

import (
	"bytes"
	"testing"
)

func TestBase91Encoding_Encode(t *testing.T) {
	data := []byte("Hello, World!")
	expected := ">OwJh>}AQ;r@@Y?F"
	result := Base91.Encode(data)
	if result != expected {
		t.Errorf("expected %s, got %s", expected, result)
	}
}

func TestBase91Encoding_Decode(t *testing.T) {
	expected := []byte("Hello, World!")
	data := Base91.Encode(expected)
	result, err := Base91.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(expected, result) {
		t.Errorf("expected %x, got %x", expected, result)
	}
}

func TestBase91Encoding_DecodeInvalidCharacter(t *testing.T) {
	data := "8OuD.RD)VcHy<U+pr`" // ` is not in the base91Encoding alphabet
	_, err := Base91.Decode(data)
	if err == nil {
		t.Fatal("expected error")
	}
}
