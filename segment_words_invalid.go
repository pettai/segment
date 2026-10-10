package segment

import "unicode/utf8"

// invalidByteAt reports whether data[i] starts no valid UTF-8 encoding:
// a lone continuation byte, a byte that never occurs in UTF-8 (0xC0, 0xC1,
// 0xF5-0xFF), or the lead byte of a sequence that is broken or, at EOF,
// cut off. A complete-looking but still unfinished sequence at the end of
// the data before EOF is not invalid yet: more bytes may complete it.
func invalidByteAt(data []byte, i int, atEOF bool) bool {
	if data[i] < utf8.RuneSelf {
		return false
	}
	if !atEOF && !utf8.FullRune(data[i:]) {
		return false
	}
	r, size := utf8.DecodeRune(data[i:])
	return r == utf8.RuneError && size == 1
}
