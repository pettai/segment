//  Copyright (c) 2015 Couchbase, Inc.
//  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
//  except in compliance with the License. You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//  Unless required by applicable law or agreed to in writing, software distributed under the
//  License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
//  either express or implied. See the License for the specific language governing permissions
//  and limitations under the License.

package segment

import "bytes"

// ipv6End checks a TokIPv6 match data[start:end] against the text after it,
// which the scanner's grammar can't see. It returns the end of the address
// (end, or less when cut back to a whole group) and whether there is one.
//
//   - A match followed by a letter or digit stopped inside a longer group,
//     because a group holds at most 4 hex digits: "fdcd:304b:f1d4::1:6019"
//     in "fdcd:304b:f1d4::1:60198", an unbracketed 5-digit port. A "::"
//     address is cut back to its last whole group ("fdcd:304b:f1d4::1"); an
//     8-group one has no shorter valid form.
//   - A match followed by ':' and more hex is either an unbracketed port or a
//     longer colon-hex run. 1-5 digits and then a boundary is a port; anything
//     else is a longer run (netfilter's "MAC=" chain, a key fingerprint), and
//     not an address.
func ipv6End(data []byte, start, end int) (int, bool) {
	if end == len(data) {
		return end, true
	}
	switch c := data[end]; {
	case isAlnumByte(c):
		tok := data[start:end]
		if !bytes.Contains(tok, []byte("::")) {
			return 0, false
		}
		cut := bytes.LastIndexByte(tok, ':')
		if tok[cut-1] == ':' {
			cut++ // keep a trailing "::"
		}
		if cut == len(tok) || cut < 8 || !bytes.ContainsAny(tok[:cut], "0123456789") {
			return 0, false
		}
		return start + cut, true
	case c == ':':
		if end+1 == len(data) || !isHexByte(data[end+1]) {
			return end, true
		}
		j := end + 1
		for j < len(data) && j-end <= 6 && data[j] >= '0' && data[j] <= '9' {
			j++
		}
		if n := j - end - 1; n >= 1 && n <= 5 &&
			(j == len(data) || !(isAlnumByte(data[j]) || data[j] == ':' || data[j] == '.')) {
			return end, true
		}
		return 0, false
	case c == '.':
		if end+1 < len(data) && isAlnumByte(data[end+1]) {
			return 0, false
		}
	}
	return end, true
}

func isHexByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func isAlnumByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'
}
