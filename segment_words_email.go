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

// systemdUnitTypes are the unit type suffixes of systemd.unit(5). A templated
// unit's instance name has an email's shape ("user@1000.service"), so a
// "domain" ending in one of these is a unit. Some may also be brand
// top-level domains; an address at one of those loses its type, which is
// the cheaper mistake given how often units are logged.
var systemdUnitTypes = [...]string{
	"service", "socket", "device", "mount", "automount", "swap",
	"target", "path", "timer", "slice", "scope",
}

// emailOK checks the last label of a TokEmail match, which the grammar
// leaves loose (any letters, digits and '-'). It must be a plausible
// top-level domain -- at least 2 letters, or an IDN "xn--" label -- and
// not a systemd unit type. That rejects "SecuredCoreState@1.0-GET" (a
// version, last label "0-GET") and "serial-getty@ttyS0.service".
func emailOK(tok []byte) bool {
	tld := tok[bytes.LastIndexByte(tok, '.')+1:]
	if len(tld) > 4 && string(tld[:4]) == "xn--" {
		return true
	}
	if len(tld) < 2 {
		return false
	}
	for _, c := range tld {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			return false
		}
	}
	for _, u := range systemdUnitTypes {
		if string(tld) == u {
			return false
		}
	}
	return true
}
