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
	case SID:
		return "SID"
	case IPv6:
		return "IPv6"
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
		{"a4cf.995f.04cb", MAC}, // Cisco dotted form
		{"A4CF.995F.04CB", MAC},
		{"user@example.com", Email},
		{"first.last@mail.example.org", Email},
		{"user+tag@example.co.uk", Email},
		{"user_name@example-host.net", Email},
		// Windows Security Identifier (SDDL string form)
		{"S-1-5-18", SID}, // well-known SID (LocalSystem), minimum 3 groups
		{"S-1-5-21-3623811015-3361044348-30300820-1013", SID}, // domain SID + RID (7 groups)
		{"S-1-1-0", SID}, // well-known SID (Everyone)
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
		"2005.06.03",          // dotted date, three groups
		"10.4.1122.7",         // version string, group too long for IPv4
		"1.2.3",               // three groups only
		"3.4.5.6.7",           // five groups
		"13:31",               // no seconds
		"2026-3-8",            // unpadded date
		"deadbeef-cafe",       // short dashed hex
		"550e8400-e29b",       // truncated UUID
		"fa:3c:0d:3c:d9",      // five MAC groups
		"a4cf.995f",           // two Cisco MAC groups
		"a4cf.995f.04c",       // short last Cisco group
		"0011.2233.4455.6677", // four all-numeric groups
		"a4cf-995f-04cb",      // dash-separated groups of 4 are not Cisco's form
		"user@example",        // no dot in domain
		"@example.com",        // no local part
		"25/Aug/2026",         // CLF date without the time part
		"S-1-5",               // only 2 groups after 'S' — below the 3-group SID minimum
		"S-1",                 // only 1 group after 'S'
		"s-1-5-18",            // lowercase 's' is not the SDDL string form
	}
	extended := map[int]bool{IPv4: true, UUID: true, Email: true, MAC: true, Timestamp: true, SID: true, IPv6: true}
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
//
// MACs behave the same way in all three forms. For the Cisco form this holds
// even though a longer dotted run looks like it should be one token: UAX#29
// doesn't join a letter to a digit across '.', so without the MAC rule
// "a4cf.995f.04cb.1234" is already five tokens, and no Word match is longer
// than the MAC prefix. An all-numeric run is different -- see the guards.
func TestExtendedTypesGreedyPrefix(t *testing.T) {
	tests := []struct {
		in, first string
		want      int
	}{
		{"2026-08-255", "2026-08-25", Timestamp},
		{"fa:3c:0d:3c:d9:d5:11", "fa:3c:0d:3c:d9:d5", MAC},
		{"a4cf.995f.04cbe", "a4cf.995f.04cb", MAC},
		{"a4cf.995f.04cb.1234", "a4cf.995f.04cb", MAC},
	}
	for _, tc := range tests {
		toks, types := segmentAll(t, tc.in)
		if len(toks) < 2 || toks[0] != tc.first || types[0] != tc.want {
			t.Errorf("%q: got %q typed %s, want %s typed %s first, then the rest",
				tc.in, strings.Join(toks, "|"), typeName(types[0]), tc.first, typeName(tc.want))
		}
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
		{"0011.2233.4455", MAC},            // not one Numeric token
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

// TestCiscoMACInContext uses a RADIUS accounting line, where the
// Calling-Station-Id is in Cisco's dotted form and the NAS id in the
// dash-separated form: both must come back as MAC, neither swallowing its
// neighbours.
func TestCiscoMACInContext(t *testing.T) {
	const line = `AUTH: Access-Accept for user@example.se at Proxy=192.0.2.34 (CSI=7a0d.eb06.2612 NAS=4C-B1-CD-50-C2-18/10.70.1.22)`
	toks, types := segmentAll(t, line)
	var macs []string
	for i, ty := range types {
		if ty == MAC {
			macs = append(macs, toks[i])
		}
	}
	if strings.Join(macs, "|") != "7a0d.eb06.2612|4C-B1-CD-50-C2-18" {
		t.Errorf("got MACs %q: %s", macs, strings.Join(toks, "|"))
	}
}

// TestIPv6Recognized covers the RFC 4291 text forms. Each must come back as
// one IPv6 token.
func TestIPv6Recognized(t *testing.T) {
	for _, in := range []string{
		"2001:0db8:85a3:0000:0000:8a2e:0370:7334", // full form
		"2001:db8:85a3:0:0:8a2e:370:7334",         // leading zeros dropped
		"2a00:801:581:eeed:2d74:45ff:d67a:82a0",   // groups UAX#29 would fuse ("45ff:d67a")
		"2001:db8::1",                             // compressed
		"2001:db8::",                              // trailing "::"
		"::ffff:172.16.1.1",                       // IPv4-mapped
		"64:ff9b::192.0.2.33",                     // NAT64, dotted tail
		"fe80::1:2:3",                             // link-local
		"FE80::A00:27FF:FE4E:66A1",                // upper case
		"::1234:5678",                             // leading "::", exactly 8 bytes
		"1:2:3:4:5:6:7::",                         // 7 groups + trailing "::"
	} {
		toks, types := segmentAll(t, in)
		if len(toks) != 1 || toks[0] != in || types[0] != IPv6 {
			t.Errorf("%q: got %q typed %s, want one IPv6 token",
				in, strings.Join(toks, "|"), typeName(types[0]))
		}
	}
}

// TestIPv6Guards covers what the IPv6 rule must leave alone: short
// addresses (conformance cases among them), hex-only scope syntax, and the
// colon-separated shapes other rules own.
func TestIPv6Guards(t *testing.T) {
	for _, in := range []string{
		"::1",               // shorter than 8 bytes
		"fe80::1",           // 7 bytes
		"1::1",              // a WordBreakTest case
		"a::",               // a WordBreakTest case
		"Feed::add",         // hex-only scope syntax: no digit
		"Cafe::Bad",         // ditto
		"std::vector",       // not hex at all
		"1:2:3:4:5:6:7",     // 7 groups, no "::"
		"12345::1",          // a group longer than 4 hex digits
		"1:2:3:4:5:6:7:8:9", // 9 groups: the 8-group prefix is taken, see TestIPv6Port
	} {
		toks, types := segmentAll(t, in)
		if len(toks) == 1 && types[0] == IPv6 {
			t.Errorf("%q: wrongly typed IPv6 as a whole", in)
		}
		if in == "1:2:3:4:5:6:7:8:9" {
			continue
		}
		for i, ty := range types {
			if ty == IPv6 {
				t.Errorf("%q: token %q wrongly typed IPv6 (full split: %s)",
					in, toks[i], strings.Join(toks, "|"))
			}
		}
	}
	// The shapes other rules own keep their types.
	for _, tc := range []struct {
		in   string
		want int
	}{
		{"12:34:56:78:90:12", MAC},
		{"13:31:37", Timestamp},
		{"192.168.14.203", IPv4},
	} {
		toks, types := segmentAll(t, tc.in)
		if len(toks) != 1 || types[0] != tc.want {
			t.Errorf("%q: got %q typed %s, want %s",
				tc.in, strings.Join(toks, "|"), typeName(types[0]), typeName(tc.want))
		}
	}
}

// TestIPv6ClockShapedGroups is the case that motivated the rule: a run of
// 2-digit groups inside an address used to be taken by TokClock, cutting the
// address in two.
func TestIPv6ClockShapedGroups(t *testing.T) {
	const addr = "2604:4000:0:d:216:40:47:26"
	toks, types := segmentAll(t, "from "+addr+" port 22")
	for i, tok := range toks {
		if tok == addr && types[i] == IPv6 {
			return
		}
	}
	t.Errorf("no IPv6 token %q: %s", addr, strings.Join(toks, "|"))
}

// TestIPv6Port pins what happens to a port after an address. Bracketed, it
// is always separate. Unbracketed, it is left out when it can't be a group:
// after a full 8-group address (a 9th group is invalid) or when it has 5
// digits (a group has at most 4, so the address is cut back to its last
// whole group). A port of up to 4 digits after a "::" address is one more
// valid group, and the text alone can't say otherwise.
func TestIPv6Port(t *testing.T) {
	tests := []struct{ in, want string }{
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"2001:948:4:6:2a00:afff:fef3:82bc:443", "2001:948:4:6:2a00:afff:fef3:82bc"},
		{"2a00:801:581:eeed:2d74:45ff:d67a:82a0:40398", "2a00:801:581:eeed:2d74:45ff:d67a:82a0"},
		{"fdcd:304b:f1d4::1:60198", "fdcd:304b:f1d4::1"},
		{"2001:9b1:8826:0:155:4:14:52:52356", "2001:9b1:8826:0:155:4:14:52"},
		{"::ffff:10.1.2.3:8080", "::ffff:10.1.2.3"},
		{"2001:db8::1:443", "2001:db8::1:443"},
	}
	for _, tc := range tests {
		toks, types := segmentAll(t, tc.in)
		found := false
		for i, tok := range toks {
			if types[i] == IPv6 {
				if tok != tc.want {
					t.Errorf("%q: IPv6 token %q, want %q", tc.in, tok, tc.want)
				}
				found = true
			}
		}
		if !found {
			t.Errorf("%q: no IPv6 token: %s", tc.in, strings.Join(toks, "|"))
		}
	}
}

// TestIPv6InsideLongerRuns checks the guards against longer colon-hex runs:
// none of these is an address, and each segments exactly as it did before
// IPv6 typing existed (the expected splits come from segment 17fd421).
func TestIPv6InsideLongerRuns(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		// netfilter LOG "MAC=": dst MAC + src MAC + EtherType, colon-joined
		{"MAC=d0:94:66:1f:1e:de:d4:af:f7:ca:11:8d:08:00 SRC=x",
			"MAC|=|d0:94:66:1f:1e:de|:|d4:af:f7:ca:11:8d|:|08|:|00| |SRC|=|x"},
		// a 16-group MD5 key fingerprint
		{"MD5:5e:2a:13:9c:01:7f:aa:3b:52:6d:0e:91:c4:88:12:f0",
			"MD5|:|5e:2a:13:9c:01:7f|:|aa:3b:52:6d:0e:91|:|c4|:|88|:|12|:|f0"},
		// 20- and 32-pair SHA-1/SHA-256 fingerprints: after the leading pairs
		// go to TokMAC, exactly 8 pairs remain, which is a valid address by
		// grammar alone
		{"SHA1:5e:2a:13:9c:01:7f:aa:3b:52:6d:0e:91:c4:88:12:f0:01:02:03:04",
			"SHA1|:|5e:2a:13:9c:01:7f|:|aa:3b:52:6d:0e:91|:|c4:88:12:f0:01:02|:|03|:|04"},
		{"SHA256:5e:2a:13:9c:01:7f:aa:3b:52:6d:0e:91:c4:88:12:f0:5e:2a:13:9c:01:7f:aa:3b:52:6d:0e:91:c4:88:12:f0",
			"SHA256|:|5e:2a:13:9c:01:7f|:|aa:3b:52:6d:0e:91|:|c4:88:12:f0:5e:2a|:|13:9c:01:7f:aa:3b|:|52:6d:0e:91:c4:88|:|12|:|f0"},
		// 8 groups of exactly 2 digits
		{"10:20:30:40:50:60:70:80", "10:20:30:40:50:60|:|70|:|80"},
		// a 4-hex group running on past 4 digits in an 8-group address
		{"1:2:3:4:5:6:7:89abc", "1|:|2|:|3|:|4|:|5|:|6|:|7|:|89abc"},
	}
	for _, tc := range tests {
		toks, types := segmentAll(t, tc.in)
		if got := strings.Join(toks, "|"); got != tc.want {
			t.Errorf("%q:\n got %s\nwant %s", tc.in, got, tc.want)
		}
		for i, ty := range types {
			if ty == IPv6 {
				t.Errorf("%q: token %q typed IPv6", tc.in, toks[i])
			}
		}
	}
}
