package broker

import (
	"bytes"
	"strings"
	"testing"
)

// --- decodeExactlyOne ---------------------------------------------------------

func TestDecodeExactlyOneAcceptsWhitespaceOnlyTrailer(t *testing.T) {
	var v map[string]int
	if err := decodeExactlyOne([]byte(`{"a":1}   `+"\n\t"), &v); err != nil {
		t.Fatalf("decodeExactlyOne: whitespace-only trailer should be accepted, got: %v", err)
	}
	if v["a"] != 1 {
		t.Errorf("decodeExactlyOne: decoded value wrong: %v", v)
	}
}

func TestDecodeExactlyOneRejectsAnotherValue(t *testing.T) {
	var v map[string]int
	err := decodeExactlyOne([]byte(`{"a":1}{"b":2}`), &v)
	if err == nil {
		t.Fatal("decodeExactlyOne: expected rejection of a second JSON value, got none")
	}
}

func TestDecodeExactlyOneRejectsGarbageText(t *testing.T) {
	var v map[string]int
	err := decodeExactlyOne([]byte(`{"a":1} not json`), &v)
	if err == nil {
		t.Fatal("decodeExactlyOne: expected rejection of trailing garbage text, got none")
	}
}

func TestDecodeExactlyOneRejectsUnmatchedClosingBracket(t *testing.T) {
	// The case json.Decoder.More() misses: at the top level, More() returns
	// false when it peeks a '}' or ']', so a lone unmatched closer after a
	// complete value would slip through More()-based trailing-data checks.
	var v map[string]int
	err := decodeExactlyOne([]byte(`{"a":1}}`), &v)
	if err == nil {
		t.Fatal("decodeExactlyOne: expected rejection of an unmatched '}', got none")
	}

	var arr []int
	err = decodeExactlyOne([]byte(`[1,2]]`), &arr)
	if err == nil {
		t.Fatal("decodeExactlyOne: expected rejection of an unmatched ']', got none")
	}
}

func TestDecodeExactlyOneRejectsUnknownFields(t *testing.T) {
	var v struct {
		A int `json:"a"`
	}
	err := decodeExactlyOne([]byte(`{"a":1,"b":2}`), &v)
	if err == nil {
		t.Fatal("decodeExactlyOne: expected rejection of an unknown field, got none")
	}
}

// --- framing -------------------------------------------------------------

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	body := []byte(`{"hello":"world"}`)
	if err := writeFrame(&buf, body); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	got, err := readFrame(&buf, MaxRequestBytes)
	if err != nil {
		t.Fatalf("readFrame: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("readFrame: got %q, want %q", got, body)
	}
}

func TestReadFrameRejectsOversizeLength(t *testing.T) {
	// A frame whose declared length exceeds a small bound is refused from the
	// length prefix alone, before any body bytes are read.
	var buf bytes.Buffer
	if err := writeFrame(&buf, make([]byte, 1000)); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	if _, err := readFrame(&buf, 10); err == nil {
		t.Fatal("readFrame: expected rejection of a frame exceeding the bound, got none")
	}
}

// --- request decoding ------------------------------------------------------

func TestDecodeRequestRejectsUnknownField(t *testing.T) {
	_, err := decodeRequest([]byte(`{"protocol":1,"operation":"tea.repos-list","executable":"/bin/sh"}`))
	if err == nil {
		t.Fatal("decodeRequest: expected rejection of an unknown field, got none")
	}
	if !strings.Contains(err.Error(), "executable") {
		t.Errorf("decodeRequest: error should name the unknown field, got: %v", err)
	}
}

func TestDecodeRequestAcceptsWellFormed(t *testing.T) {
	req, err := decodeRequest([]byte(`{"protocol":1,"operation":"tea.repos-list","inputs":{"owner":"acme"}}`))
	if err != nil {
		t.Fatalf("decodeRequest: unexpected error: %v", err)
	}
	if req.Protocol != 1 || req.Operation != "tea.repos-list" || req.Inputs["owner"] != "acme" {
		t.Errorf("decodeRequest: got %+v", req)
	}
}

// --- operation syntax ------------------------------------------------------

func TestSplitOperationRef(t *testing.T) {
	cases := []struct {
		in       string
		wantOK   bool
		wantCons string
		wantOp   string
	}{
		{"tea.repos-list", true, "tea", "repos-list"},
		{"tea", false, "", ""},
		{"tea.repos.list", false, "", ""}, // second dot: neither half's shape allows a dot
		{".repos-list", false, "", ""},
		{"tea.", false, "", ""},
		{"", false, "", ""},
		{"TEA.repos-list", false, "", ""}, // uppercase not in the name shape
	}
	for _, c := range cases {
		cons, op, ok := splitOperationRef(c.in)
		if ok != c.wantOK || cons != c.wantCons || op != c.wantOp {
			t.Errorf("splitOperationRef(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.in, cons, op, ok, c.wantCons, c.wantOp, c.wantOK)
		}
	}
}
