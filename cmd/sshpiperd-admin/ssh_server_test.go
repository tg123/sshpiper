package main

import (
	"reflect"
	"testing"
)

func TestSplitArgs(t *testing.T) {
	cases := []struct {
		in      string
		want    []string
		wantErr bool
	}{
		{"", []string{}, false},
		{"   ", []string{}, false},
		{"list", []string{"list"}, false},
		{"list --json", []string{"list", "--json"}, false},
		{"kill abc-123", []string{"kill", "abc-123"}, false},
		{"stream  abc   --format   asciicast", []string{"stream", "abc", "--format", "asciicast"}, false},
		{`kill "id with spaces"`, []string{"kill", "id with spaces"}, false},
		{`kill 'id with spaces'`, []string{"kill", "id with spaces"}, false},
		{`echo "a\"b"`, []string{"echo", `a"b`}, false},
		{`echo a\ b`, []string{"echo", "a b"}, false},
		{`bad "unterminated`, nil, true},
		{`bad 'unterminated`, nil, true},
		{`bad \`, nil, true},
	}

	for _, tc := range cases {
		got, err := splitArgs(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("splitArgs(%q): want error, got %v", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("splitArgs(%q): unexpected error %v", tc.in, err)
			continue
		}
		if len(got) == 0 && len(tc.want) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("splitArgs(%q): got %#v, want %#v", tc.in, got, tc.want)
		}
	}
}

func TestParseStringPayload(t *testing.T) {
	// SSH "string" wire format: uint32 length prefix + bytes.
	cases := []struct {
		payload []byte
		want    string
	}{
		{[]byte{0, 0, 0, 4, 'l', 'i', 's', 't'}, "list"},
		{[]byte{0, 0, 0, 0}, ""},
		{[]byte{0, 0}, ""},                  // too short
		{[]byte{0, 0, 0, 10, 'a', 'b'}, ""}, // length larger than payload
	}
	for _, tc := range cases {
		if got := parseStringPayload(tc.payload); got != tc.want {
			t.Errorf("parseStringPayload(%v): got %q, want %q", tc.payload, got, tc.want)
		}
	}
}
