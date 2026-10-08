//  Copyright (c) 2015 Couchbase, Inc.
//  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
//  except in compliance with the License. You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//  Unless required by applicable law or agreed to in writing, software distributed under the
//  License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
//  either express or implied. See the License for the specific language governing permissions
//  and limitations under the License.

package segment

// numericListCut looks at a WordNumeric match for a list of numbers joined
// by ',' or ';'. UAX#29 joins digits across those (MidNum, for "1,000"), so
// a list written without spaces comes back as one Number and an IPv4
// address inside it is never typed: nrpe's "127.0.0.1,127.0.1.1,…",
// ProxySQL's "(10,89.46.21.95,3306,13897734)". When one of the list's
// elements is a valid IPv4 address (octets <= 255), it returns the length of
// the first element, to be emitted alone -- typed IPv4 if it is one -- and
// the rest scanned again from the separator, element by element. Otherwise
// it returns 0 and the match stands.
//
// A European-format amount of a billion or more with decimals
// ("1.000.000.000,50") is cut too; that is the price of not knowing what
// the list is.
func numericListCut(tok []byte) (n int, ipv4 bool) {
	first, hasAddr := -1, false
	for start, i := 0, 0; i <= len(tok); i++ {
		if i < len(tok) && tok[i] != ',' && tok[i] != ';' {
			continue
		}
		if first < 0 {
			if i == len(tok) {
				return 0, false // no separator
			}
			first = i
		}
		if isIPv4Bytes(tok[start:i]) {
			hasAddr = true
		}
		start = i + 1
	}
	if !hasAddr {
		return 0, false
	}
	return first, isDottedQuad(tok[:first])
}

// isDottedQuad reports whether b has TokIPv4's shape: four groups of 1-3
// digits.
func isDottedQuad(b []byte) bool {
	groups, digits := 1, 0
	for _, c := range b {
		switch {
		case c >= '0' && c <= '9':
			digits++
			if digits > 3 {
				return false
			}
		case c == '.':
			if digits == 0 {
				return false
			}
			groups++
			digits = 0
		default:
			return false
		}
	}
	return groups == 4 && digits > 0
}

// isIPv4Bytes is isDottedQuad with every octet <= 255.
func isIPv4Bytes(b []byte) bool {
	if !isDottedQuad(b) {
		return false
	}
	n := 0
	for i := 0; i <= len(b); i++ {
		if i == len(b) || b[i] == '.' {
			if n > 255 {
				return false
			}
			n = 0
			continue
		}
		n = n*10 + int(b[i]-'0')
	}
	return true
}
