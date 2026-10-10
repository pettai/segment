package segment

import (
	"bytes"
	"reflect"
	"testing"
)

type typedTok struct {
	text string
	typ  int
}

func segmentTyped(t *testing.T, s *Segmenter) []typedTok {
	t.Helper()
	var out []typedTok
	for s.Segment() {
		out = append(out, typedTok{s.Text(), s.Type()})
	}
	if err := s.Err(); err != nil {
		t.Fatalf("Err() = %v", err)
	}
	return out
}

// Invalid UTF-8 used to stop the scan silently: a token directly followed
// by an invalid byte was held back as if more input could complete it,
// even at EOF, so "abc \xff def" gave only "abc" and Err() was nil.
func TestInvalidUTF8(t *testing.T) {
	cases := []struct {
		in   string
		want []typedTok
	}{
		{"abc \xff def", []typedTok{{"abc", Letter}, {" ", None}, {"\xff", Invalid}, {" ", None}, {"def", Letter}}},
		{"abc \xff\xfe def", []typedTok{{"abc", Letter}, {" ", None}, {"\xff\xfe", Invalid}, {" ", None}, {"def", Letter}}},
		{"a\xffb", []typedTok{{"a", Letter}, {"\xff", Invalid}, {"b", Letter}}},
		{"character: 0\x84", []typedTok{{"character", Letter}, {":", None}, {" ", None}, {"0", Number}, {"\x84", Invalid}}},
		{"a \xe2\x82 b", []typedTok{{"a", Letter}, {" ", None}, {"\xe2\x82", Invalid}, {" ", None}, {"b", Letter}}},
		{"end \xe2\x82", []typedTok{{"end", Letter}, {" ", None}, {"\xe2\x82", Invalid}}},
		{"\xc0!\xc0\"", []typedTok{{"\xc0", Invalid}, {"!", None}, {"\xc0", Invalid}, {"\"", None}}},
		{"save '\xc3 x'", []typedTok{{"save", Letter}, {" ", None}, {"'", None}, {"\xc3", Invalid}, {" ", None}, {"x", Letter}, {"'", None}}},
		// U+FFFD is a valid character, not invalid input.
		{"a \uFFFD b", []typedTok{{"a", Letter}, {" ", None}, {"\uFFFD", None}, {" ", None}, {"b", Letter}}},
		{"10.1.2.3 \xff", []typedTok{{"10.1.2.3", IPv4}, {" ", None}, {"\xff", Invalid}}},
	}
	for _, c := range cases {
		got := segmentTyped(t, NewSegmenterDirect([]byte(c.in)))
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q:\n got %q\nwant %q", c.in, got, c.want)
		}
		slow := segmentTyped(t, NewSegmenter(&slowReader{1, bytes.NewReader([]byte(c.in))}))
		if !reflect.DeepEqual(slow, c.want) {
			t.Errorf("%q, 1-byte reader:\n got %q\nwant %q", c.in, slow, c.want)
		}
	}
}

// Every input byte comes back in some token, in order, whether the input
// is read at once or one byte at a time (where a multi-byte character
// arrives split and must be waited for, not taken as invalid).
func TestSegmentationIsLossless(t *testing.T) {
	inputs := [][]byte{
		[]byte("caf\xc3\xa9 \xe3\x80\xb1\x01 \xf0\x9f\x98\x80 ok"),
		[]byte("\xff\xfe\xfd"), []byte("\x80"), []byte("\xe2\x82"), []byte("\xf0\x9f\x98"),
		[]byte("2001:db8::1 \xc0 user@example.org\x84 2026-09-22T17:00:01+00:00\xff"),
	}
	for _, tc := range unicodeWordTests {
		inputs = append(inputs, tc.input)
	}
	join := func(ts []typedTok) []byte {
		var b []byte
		for _, x := range ts {
			b = append(b, x.text...)
		}
		return b
	}
	for _, in := range inputs {
		if got := join(segmentTyped(t, NewSegmenterDirect(in))); !bytes.Equal(got, in) {
			t.Errorf("%q: tokens join to %q", in, got)
		}
		if got := join(segmentTyped(t, NewSegmenter(&slowReader{1, bytes.NewReader(in)}))); !bytes.Equal(got, in) {
			t.Errorf("%q, 1-byte reader: tokens join to %q", in, got)
		}
	}
}

func TestErrNoProgress(t *testing.T) {
	s := NewSegmenterDirect([]byte("abc"))
	s.SetSegmenter(func(data []byte, atEOF bool) (int, []byte, int, error) { return 0, nil, 0, nil })
	if s.Segment() {
		t.Fatal("Segment() = true for a segment function that never advances")
	}
	if s.Err() != ErrNoProgress {
		t.Fatalf("Err() = %v, want ErrNoProgress", s.Err())
	}
}
