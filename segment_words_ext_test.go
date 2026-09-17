//  Copyright (c) 2015 Couchbase, Inc.
//  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
//  except in compliance with the License. You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//  Unless required by applicable law or agreed to in writing, software distributed under the
//  License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
//  either express or implied. See the License for the specific language governing permissions
//  and limitations under the License.

package segment

import (
	"strings"
	"testing"
)

func typeName(t int) string {
	switch t {
	case None:
		return "None"
	case Number:
		return "Number"
	case Letter:
		return "Letter"
	case Kana:
		return "Kana"
	case Ideo:
		return "Ideo"
	case IPv4:
		return "IPv4"
	case UUID:
		return "UUID"
	case Email:
		return "Email"
	case MAC:
		return "MAC"
	case Timestamp:
		return "Timestamp"
	}
	return "?"
}

func segmentAll(t *testing.T, in string) ([]string, []int) {
	t.Helper()
	s := NewSegmenterDirect([]byte(in))
	var toks []string
	var types []int
	for s.Segment() {
		toks = append(toks, s.Text())
		types = append(types, s.Type())
	}
	if err := s.Err(); err != nil {
		t.Fatalf("segmenting %q: %v", in, err)
	}
	return toks, types
}

// TestExtendedTypesRecognized covers the non-UAX#29 token shapes this fork
// adds. Each input must come back as exactly one token carrying the given type.
func TestExtendedTypesRecognized(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		// RFC 3339 / ISO 8601
		{"2026-08-25T13:31:37+00:00", Timestamp},
		{"2026-08-25T13:31:37Z", Timestamp},
		{"2026-08-25T13:31:37.854652267Z", Timestamp},
		{"2026-08-25T13:31:37.123456+01:00", Timestamp},
		{"2026-08-25t13:31:37z", Timestamp},
		{"2026-08-25", Timestamp},
		// Common Log Format / HAProxy
		{"25/Aug/2026:08:59:50", Timestamp},
		{"25/Aug/2026:08:59:50.112", Timestamp},
		{"8/Jan/2026:00:00:01", Timestamp},
		// bare wall clock
		{"13:31:37", Timestamp},
		{"00:00:00", Timestamp},
		{"13:31:37.500", Timestamp},
		// values
		{"192.168.14.203", IPv4},
		{"10.0.3.17", IPv4},
		{"255.255.255.255", IPv4},
		{"550e8400-e29b-41d4-a716-446655440000", UUID},
		{"6BA7B810-9DAD-11D1-80B4-00C04FD430C8", UUID},
		{"fa:3c:0d:3c:d9:d5", MAC},
		{"3a-22-4f-d9-b0-da", MAC},
		{"D4:AF:F7:CA:12:83", MAC},
		{"user@example.com", Email},
		{"first.last@mail.example.org", Email},
		{"user+tag@example.co.uk", Email},
		{"user_name@example-host.net", Email},
	}
	for _, tc := range tests {
		toks, types := segmentAll(t, tc.in)
		if len(toks) != 1 {
			t.Errorf("%q: got %d tokens %q, want 1",
				tc.in, len(toks), strings.Join(toks, "|"))
			continue
		}
		if toks[0] != tc.in {
			t.Errorf("%q: token text is %q", tc.in, toks[0])
		}
		if types[0] != tc.want {
			t.Errorf("%q: type is %s, want %s",
				tc.in, typeName(types[0]), typeName(tc.want))
		}
	}
}

// TestPrefixedUUIDRecognized covers "uuid:"/"urn:uuid:" scheme prefixes
// fused directly onto a UUID's first hex group by the ':' MidLetter joiner.
// Before UuidPrefix was added to TokUUID, the generic Word rule always won
// this fight (e.g. "urn:uuid:e2eb2dca" came back as one Letter token,
// followed by the rest of the UUID's dash-separated groups independently
// typed Letter or, if a group happened to be all-digits, Number) — see
// TokUUID's comment. Each of these must now come back as exactly one
// UUID-typed token, prefix included, case-insensitively.
func TestPrefixedUUIDRecognized(t *testing.T) {
	tests := []string{
		"uuid:550e8400-e29b-41d4-a716-446655440000",
		"UUID:550e8400-e29b-41d4-a716-446655440000",
		"urn:uuid:e2eb2dca-a95e-40cd-a68f-913ec07b7cef",
		"URN:UUID:e2eb2dca-a95e-40cd-a68f-913ec07b7cef",
		"Urn:Uuid:e2eb2dca-a95e-40cd-a68f-913ec07b7cef",
		// Regression case: an interior hex group that happens to be all
		// digits must not fragment the match, unlike the pre-fix behavior
		// where "1234" here was independently typed Number.
		"urn:uuid:a2e34afe-1234-44ad-aa6d-257034ac0832",
	}
	for _, in := range tests {
		toks, types := segmentAll(t, in)
		if len(toks) != 1 {
			t.Errorf("%q: got %d tokens %q, want 1",
				in, len(toks), strings.Join(toks, "|"))
			continue
		}
		if toks[0] != in {
			t.Errorf("%q: token text is %q", in, toks[0])
		}
		if types[0] != UUID {
			t.Errorf("%q: type is %s, want UUID", in, typeName(types[0]))
		}
	}
}

// TestPrefixedUUIDGuards covers prefix-shaped text that must NOT be fused
// into the UUID-typed token: TokUUID's UuidPrefix is scoped to exactly
// "uuid:"/"urn:uuid:", not any colon-joined word before a hex-dash run. An
// unrelated or near-miss prefix must stay its own separate token (or, for a
// truncated UUID, prevent the UUID type from firing at all) — the bare UUID
// itself may still correctly type standalone when nothing joins it to what
// precedes it (e.g. a leading digit breaks the Letter-colon-Letter join
// that fuses "uuid:e2eb..." in the first place).
func TestPrefixedUUIDGuards(t *testing.T) {
	const uuid = "550e8400-e29b-41d4-a716-446655440000"
	tests := []struct {
		in       string
		wantToks []string // expected token split; UUID type checked on the "uuid" one
	}{
		{"session:" + uuid, []string{"session", ":", uuid}}, // unrelated prefix
		{"uuidx:" + uuid, []string{"uuidx", ":", uuid}},     // near-miss prefix
	}
	for _, tc := range tests {
		toks, types := segmentAll(t, tc.in)
		if strings.Join(toks, "|") != strings.Join(tc.wantToks, "|") {
			t.Errorf("%q: got tokens %q, want %q", tc.in, toks, tc.wantToks)
			continue
		}
		if types[len(types)-1] != UUID {
			t.Errorf("%q: last token %q should still type as a standalone UUID, got %s",
				tc.in, toks[len(toks)-1], typeName(types[len(types)-1]))
		}
	}

	notTyped := []string{
		"uuid:550e8400-e29b", // prefix + truncated UUID: must not type at all
	}
	for _, in := range notTyped {
		toks, types := segmentAll(t, in)
		for i, ty := range types {
			if ty == UUID {
				t.Errorf("%q: token %q wrongly typed UUID (full split: %s)",
					in, toks[i], strings.Join(toks, "|"))
			}
		}
	}
}

// TestExtendedTypesGuards covers shapes that must NOT be claimed by the new
// rules. These are the false positives the grammars were tightened against:
// dotted dates and version strings are not IPv4, short or unpadded time-like
// strings are not timestamps, and short dashed hex is not a UUID.
func TestExtendedTypesGuards(t *testing.T) {
	notTyped := []string{
		"2005.06.03",     // dotted date, three groups
		"10.4.1122.7",    // version string, group too long for IPv4
		"1.2.3",          // three groups only
		"3.4.5.6.7",      // five groups
		"13:31",          // no seconds
		"2026-3-8",       // unpadded date
		"deadbeef-cafe",  // short dashed hex
		"550e8400-e29b",  // truncated UUID
		"fa:3c:0d:3c:d9", // five MAC groups
		"user@example",   // no dot in domain
		"@example.com",   // no local part
		"25/Aug/2026",    // CLF date without the time part
	}
	extended := map[int]bool{IPv4: true, UUID: true, Email: true, MAC: true, Timestamp: true}
	for _, in := range notTyped {
		toks, types := segmentAll(t, in)
		for i, ty := range types {
			if extended[ty] {
				t.Errorf("%q: token %q wrongly typed %s (full split: %s)",
					in, toks[i], typeName(ty), strings.Join(toks, "|"))
			}
		}
	}
}

// TestExtendedTypesGreedyPrefix documents an accepted consequence of
// longest-match scanning: when a valid shape is followed immediately by extra
// characters that no rule can absorb, the valid prefix is still typed and the
// remainder becomes its own token. This mirrors how UAX#29's own Word rule
// behaves, and the shapes it applies to ("2026-08-255") do not occur in real
// log output. Recorded as a test so the behaviour is intentional, not a
// surprise for the next reader.
func TestExtendedTypesGreedyPrefix(t *testing.T) {
	toks, types := segmentAll(t, "2026-08-255")
	if len(toks) != 2 || toks[0] != "2026-08-25" || types[0] != Timestamp {
		t.Errorf("got %q typed %s, want 2026-08-25|5 with Timestamp first",
			strings.Join(toks, "|"), typeName(types[0]))
	}
}

// TestExtendedTypesPrecedence pins the scanner's tie-breaking. An all-numeric
// MAC is the same length as several other candidates; it must stay a MAC.
func TestExtendedTypesPrecedence(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"12:34:56:78:90:12", MAC},         // not three chained clocks
		{"2026-08-25T13:31:37", Timestamp}, // not a date followed by a clock
	}
	for _, tc := range tests {
		toks, types := segmentAll(t, tc.in)
		if len(toks) != 1 || types[0] != tc.want {
			t.Errorf("%q: got %d tokens %q typed %s, want 1 token typed %s",
				tc.in, len(toks), strings.Join(toks, "|"),
				typeName(types[0]), typeName(tc.want))
		}
	}
}

// TestExtendedTypesInContext checks the rules fire inside a realistic line and
// leave the surrounding UAX#29 segmentation alone.
func TestExtendedTypesInContext(t *testing.T) {
	const line = `<134>1 2026-08-25T08:57:33+00:00 host-02 haproxy 8 - - 10.16.1.1:55924 [25/Aug/2026:08:57:33.838] ok`
	toks, types := segmentAll(t, line)
	got := map[int]int{}
	for _, ty := range types {
		got[ty]++
	}
	if got[Timestamp] != 2 {
		t.Errorf("got %d Timestamp tokens, want 2 (header + CLF): %s",
			got[Timestamp], strings.Join(toks, "|"))
	}
	if got[IPv4] != 1 {
		t.Errorf("got %d IPv4 tokens, want 1: %s", got[IPv4], strings.Join(toks, "|"))
	}
}
