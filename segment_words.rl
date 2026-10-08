//  Copyright (c) 2015 Couchbase, Inc.
//  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file
//  except in compliance with the License. You may obtain a copy of the License at
//    http://www.apache.org/licenses/LICENSE-2.0
//  Unless required by applicable law or agreed to in writing, software distributed under the
//  License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
//  either express or implied. See the License for the specific language governing permissions
//  and limitations under the License.

// +build BUILDTAGS

package segment

import (
  "fmt"
  "unicode/utf8"
)

var RagelFlags = "RAGELFLAGS"

var ParseError = fmt.Errorf("unicode word segmentation parse error")

// Word Types
const (
  None = iota
  Number
  Letter
  Kana
  Ideo
  // Non-UAX#29 extensions: token shapes that carry a semantic type in machine
  // logs. Recognized by the same scanner DFA, so they arrive already whole and
  // already classified -- no downstream re-assembly.
  //
  // Every added rule matches at least 8 bytes, so none can collide with the
  // UCD WordBreakTest strings (the longest made only of hex digits, ':' and
  // '.' is 4 bytes). IPv6 is held to that bar explicitly: "a::" and "1::1"
  // are valid addresses and also conformance cases that must split, so an
  // IPv6 address shorter than 8 bytes ("::1", "fe80::1") is not typed here
  // and is left to the caller.
  IPv4
  UUID
  Email
  MAC
  Timestamp
  SID
  IPv6
)

%%{
  machine s;
  write data;
}%%

func segmentWords(data []byte, maxTokens int, atEOF bool, val [][]byte, types []int) ([][]byte, []int, int, error) {
  cs, p, pe := 0, 0, len(data)
  cap := maxTokens
  if cap < 0 {
    cap = 1000
  }
  if val == nil {
    val = make([][]byte, 0, cap)
  }
  if types == nil {
    types = make([]int, 0, cap)
  }

  // added for scanner
  ts := 0
  te := 0
  act := 0
  eof := pe
  _ = ts // compiler not happy
  _ = te
  _ = act

  // our state
  startPos := 0
  // the position where TokIPv6 is switched off, after finishIPv6Token
  // rejected a match starting there and rescanned it (see ipv6End)
  noIPv6At := -1
  endPos := 0
  totalConsumed := 0
  %%{

  include SCRIPTS "ragel/uscript.rl";
  include WB "ragel/uwb.rl";

  action startToken {
    startPos = p
  }

  action endToken {
    endPos = p
  }

  action finishIPv4Token {
    if !atEOF {
      return val, types, totalConsumed, nil
    }
    val = append(val, data[startPos:endPos+1])
    types = append(types, IPv4)
    totalConsumed = endPos+1
    if maxTokens > 0 && len(val) >= maxTokens {
      return val, types, totalConsumed, nil
    }
  }

  action finishUUIDToken {
    if !atEOF {
      return val, types, totalConsumed, nil
    }
    val = append(val, data[startPos:endPos+1])
    types = append(types, UUID)
    totalConsumed = endPos+1
    if maxTokens > 0 && len(val) >= maxTokens {
      return val, types, totalConsumed, nil
    }
  }

  action finishEmailToken {
    if !atEOF {
      return val, types, totalConsumed, nil
    }
    val = append(val, data[startPos:endPos+1])
    types = append(types, Email)
    totalConsumed = endPos+1
    if maxTokens > 0 && len(val) >= maxTokens {
      return val, types, totalConsumed, nil
    }
  }

  action finishMACToken {
    if !atEOF {
      return val, types, totalConsumed, nil
    }
    val = append(val, data[startPos:endPos+1])
    types = append(types, MAC)
    totalConsumed = endPos+1
    if maxTokens > 0 && len(val) >= maxTokens {
      return val, types, totalConsumed, nil
    }
  }

  action finishSIDToken {
    if !atEOF {
      return val, types, totalConsumed, nil
    }
    val = append(val, data[startPos:endPos+1])
    types = append(types, SID)
    totalConsumed = endPos+1
    if maxTokens > 0 && len(val) >= maxTokens {
      return val, types, totalConsumed, nil
    }
  }

  action ipv6Allowed { ts != noIPv6At }

  action finishIPv6Token {
    if !atEOF {
      return val, types, totalConsumed, nil
    }
    if end, ok := ipv6End(data, startPos, endPos+1); !ok {
      // Not an address in this context: scan the same bytes again
      // without TokIPv6, which gives what UAX#29 and the other rules make
      // of them.
      noIPv6At = startPos
      fexec startPos;
    } else {
      val = append(val, data[startPos:end])
      types = append(types, IPv6)
      totalConsumed = end
      if end != endPos+1 {
        fexec end;
      }
      if maxTokens > 0 && len(val) >= maxTokens {
        return val, types, totalConsumed, nil
      }
    }
  }

  action finishTimestampToken {
    if !atEOF {
      return val, types, totalConsumed, nil
    }
    val = append(val, data[startPos:endPos+1])
    types = append(types, Timestamp)
    totalConsumed = endPos+1
    if maxTokens > 0 && len(val) >= maxTokens {
      return val, types, totalConsumed, nil
    }
  }

  action finishNumericToken {
    if !atEOF {
      return val, types, totalConsumed, nil
    }

    val = append(val, data[startPos:endPos+1])
    types = append(types, Number)
    totalConsumed = endPos+1
    if maxTokens > 0 && len(val) >= maxTokens {
      return val, types, totalConsumed, nil
    }
  }

  action finishHangulToken {
    if endPos+1 == pe && !atEOF {
      return val, types, totalConsumed, nil
    } else if dr, size := utf8.DecodeRune(data[endPos+1:]); dr == utf8.RuneError && size == 1 {
      return val, types, totalConsumed, nil
    }

    val = append(val, data[startPos:endPos+1])
    types = append(types, Letter)
    totalConsumed = endPos+1
    if maxTokens > 0 && len(val) >= maxTokens {
      return val, types, totalConsumed, nil
    }
  }

  action finishKatakanaToken {
    if endPos+1 == pe && !atEOF {
      return val, types, totalConsumed, nil
    } else if dr, size := utf8.DecodeRune(data[endPos+1:]); dr == utf8.RuneError && size == 1 {
      return val, types, totalConsumed, nil
    }

    val = append(val, data[startPos:endPos+1])
    types = append(types, Ideo)
    totalConsumed = endPos+1
    if maxTokens > 0 && len(val) >= maxTokens {
      return val, types, totalConsumed, nil
    }
  }

  action finishWordToken {
    if !atEOF {
      return val, types, totalConsumed, nil
    }
    val = append(val, data[startPos:endPos+1])
    types = append(types, Letter)
    totalConsumed = endPos+1
    if maxTokens > 0 && len(val) >= maxTokens {
      return val, types, totalConsumed, nil
    }
  }

  action finishHanToken {
    if endPos+1 == pe && !atEOF {
      return val, types, totalConsumed, nil
    } else if dr, size := utf8.DecodeRune(data[endPos+1:]); dr == utf8.RuneError && size == 1 {
      return val, types, totalConsumed, nil
    }

    val = append(val, data[startPos:endPos+1])
    types = append(types, Ideo)
    totalConsumed = endPos+1
    if maxTokens > 0 && len(val) >= maxTokens {
      return val, types, totalConsumed, nil
    }
  }

  action finishHiraganaToken {
    if endPos+1 == pe && !atEOF {
      return val, types, totalConsumed, nil
    } else if dr, size := utf8.DecodeRune(data[endPos+1:]); dr == utf8.RuneError && size == 1 {
      return val, types, totalConsumed, nil
    }

    val = append(val, data[startPos:endPos+1])
    types = append(types, Ideo)
    totalConsumed = endPos+1
    if maxTokens > 0 && len(val) >= maxTokens {
      return val, types, totalConsumed, nil
    }
  }

  action finishNoneToken {
    lastPos := startPos
    for lastPos <= endPos {
      _, size := utf8.DecodeRune(data[lastPos:])
      lastPos += size
    }
    endPos = lastPos -1
    p = endPos

    if endPos+1 == pe && !atEOF {
      return val, types, totalConsumed, nil
    } else if dr, size := utf8.DecodeRune(data[endPos+1:]); dr == utf8.RuneError && size == 1 {
      return val, types, totalConsumed, nil
    }
    // otherwise, consume this as well
    val = append(val, data[startPos:endPos+1])
    types = append(types, None)
    totalConsumed = endPos+1
    if maxTokens > 0 && len(val) >= maxTokens {
      return val, types, totalConsumed, nil
    }
  }

  HangulEx = Hangul ( Extend | Format )*;
  HebrewOrALetterEx = ( Hebrew_Letter | ALetter ) ( Extend | Format )*;
  NumericEx = Numeric ( Extend | Format )*;
  KatakanaEx = Katakana ( Extend | Format )*;
  MidLetterEx = ( MidLetter | MidNumLet | Single_Quote ) ( Extend | Format )*;
  MidNumericEx = ( MidNum | MidNumLet | Single_Quote ) ( Extend | Format )*;
  ExtendNumLetEx = ExtendNumLet ( Extend | Format )*;
  HanEx = Han ( Extend | Format )*;
  HiraganaEx = Hiragana ( Extend | Format )*;
  SingleQuoteEx = Single_Quote ( Extend | Format )*;
  DoubleQuoteEx = Double_Quote ( Extend | Format )*;
  HebrewLetterEx = Hebrew_Letter ( Extend | Format )*;
  RegionalIndicatorEx = Regional_Indicator ( Extend | Format )*;
  NLCRLF = Newline | CR | LF;
  OtherEx = ^(NLCRLF) ( Extend | Format )* ;

  # UAX#29 WB8.   Numeric × Numeric
  #        WB11.  Numeric (MidNum | MidNumLet | Single_Quote) × Numeric
  #       WB12.  Numeric × (MidNum | MidNumLet | Single_Quote) Numeric
  #       WB13a. (ALetter | Hebrew_Letter | Numeric | Katakana | ExtendNumLet) × ExtendNumLet
  #       WB13b. ExtendNumLet × (ALetter | Hebrew_Letter | Numeric | Katakana)
  #
  WordNumeric = ( ( ExtendNumLetEx )* NumericEx ( ( ( ExtendNumLetEx )* | MidNumericEx ) NumericEx )* ( ExtendNumLetEx )* ) >startToken @endToken;

  # subset of the below for typing purposes only!
  WordHangul = ( HangulEx )+ >startToken @endToken;
  WordKatakana = ( KatakanaEx )+ >startToken @endToken;

  # UAX#29 WB5.   (ALetter | Hebrew_Letter) × (ALetter | Hebrew_Letter)
  #       WB6.   (ALetter | Hebrew_Letter) × (MidLetter | MidNumLet | Single_Quote) (ALetter | Hebrew_Letter)
  #       WB7.   (ALetter | Hebrew_Letter) (MidLetter | MidNumLet | Single_Quote) × (ALetter | Hebrew_Letter)
  #       WB7a.  Hebrew_Letter × Single_Quote
  #       WB7b.  Hebrew_Letter × Double_Quote Hebrew_Letter
  #       WB7c.  Hebrew_Letter Double_Quote × Hebrew_Letter
  #       WB9.   (ALetter | Hebrew_Letter) × Numeric
  #       WB10.  Numeric × (ALetter | Hebrew_Letter)
  #       WB13.  Katakana × Katakana
  #       WB13a. (ALetter | Hebrew_Letter | Numeric | Katakana | ExtendNumLet) × ExtendNumLet
  #       WB13b. ExtendNumLet × (ALetter | Hebrew_Letter | Numeric | Katakana)
  #
  # Marty -deviated here to allow for (ExtendNumLetEx x ExtendNumLetEx) part of 13a
  #
  Word = ( ( ExtendNumLetEx )* ( KatakanaEx ( ( ExtendNumLetEx )* KatakanaEx )*
                             | ( HebrewLetterEx ( SingleQuoteEx | DoubleQuoteEx HebrewLetterEx )
                               | NumericEx ( ( ( ExtendNumLetEx )* | MidNumericEx ) NumericEx )*
                               | HebrewOrALetterEx ( ( ( ExtendNumLetEx )* | MidLetterEx ) HebrewOrALetterEx )*
                               |ExtendNumLetEx
                               )+
                             )
         (
          ( ExtendNumLetEx )+ ( KatakanaEx ( ( ExtendNumLetEx )* KatakanaEx )*
                              | ( HebrewLetterEx ( SingleQuoteEx | DoubleQuoteEx HebrewLetterEx )
                                | NumericEx ( ( ( ExtendNumLetEx )* | MidNumericEx ) NumericEx )*
                                | HebrewOrALetterEx ( ( ( ExtendNumLetEx )* | MidLetterEx ) HebrewOrALetterEx )*
                                )+
                              )
         )* ExtendNumLetEx*) >startToken @endToken;

  # UAX#29 WB14.  Any ÷ Any
  WordHan = HanEx >startToken @endToken;
  WordHiragana = HiraganaEx >startToken @endToken;

  WordExt = ( ( Extend | Format )* ) >startToken @endToken; # maybe plus not star

  WordCRLF = (CR LF) >startToken @endToken;

  WordCR = CR >startToken @endToken;

  WordLF = LF >startToken @endToken;

  WordNL = Newline >startToken @endToken;

  WordRegional = (RegionalIndicatorEx+) >startToken @endToken;

  Other = OtherEx >startToken @endToken;

  # ---- Non-UAX#29 extensions -------------------------------------------
  # ASCII-only byte classes; these token shapes never contain non-ASCII.
  ADigit = 0x30..0x39;
  AHex   = 0x30..0x39 | 0x41..0x46 | 0x61..0x66;
  AAlnum = 0x30..0x39 | 0x41..0x5A | 0x61..0x7A;
  ADot   = 0x2E;
  AColon = 0x3A;
  ADash  = 0x2D;
  AAt    = 0x40;

  # Dotted quad. UAX#29 already merges this into one Numeric token (MidNumLet
  # joins Numeric x Numeric), so the gain here is the TYPE, not the merge.
  TokIPv4 = ( ADigit{1,3} ADot ADigit{1,3} ADot ADigit{1,3} ADot ADigit{1,3} )
            >startToken @endToken;

  # A "uuid:" or "urn:uuid:" scheme prefix (case-insensitive) fused directly
  # onto a UUID's first hex group -- e.g. "urn:uuid:e2eb2dca-...". ':' is a
  # UAX#29 MidLetter joiner, so without this, "urn:uuid:e2eb2dca" (prefix
  # plus the UUID's first hex group) is consumed by the generic Word rule as
  # one Letter token before TokUUID below ever gets a chance to start
  # matching at the hex digits; the UUID then permanently fails to
  # recognize as a whole, and any of its remaining dash-separated hex
  # groups that happen to be all-digits gets independently typed Number.
  # Narrowly scoped to these two literal spellings (not "any word ending in
  # a colon") to avoid swallowing unrelated colon-joined text into a
  # UUID-typed token.
  UuidPrefixUUID = (0x75|0x55) (0x75|0x55) (0x69|0x49) (0x64|0x44) AColon; # uuid: (any case)
  UuidPrefixURN  = (0x75|0x55) (0x72|0x52) (0x6E|0x4E) AColon;             # urn: (any case)
  UuidPrefix = ( UuidPrefixURN )? UuidPrefixUUID;

  # 8-4-4-4-12, optionally preceded by UuidPrefix above. '-' is not a UAX#29
  # joiner, so without the UUID type this shatters into 9 tokens.
  TokUUID = ( UuidPrefix? AHex{8} ADash AHex{4} ADash AHex{4} ADash AHex{4} ADash AHex{12} )
            >startToken @endToken;

  # 6 groups of 2 hex, colon- or dash-separated, or Cisco's 3 groups of 4 hex,
  # dot-separated ("a4cf.995f.04cb", as in IOS/WLC output and RADIUS
  # Calling-Station-Id). Kept ahead of TokClock so an all-numeric MAC still
  # wins on length rather than matching as a wall clock, and ahead of
  # WordNumeric so an all-numeric Cisco MAC ("0011.2233.4455", which UAX#29
  # already joins into one Numeric token) gets the MAC type on the tie. A
  # longer all-numeric run ("0011.2233.4455.6677") is still one Numeric
  # token, since longest match wins; a longer mixed run gets a MAC prefix,
  # like the other two forms (see TestExtendedTypesGreedyPrefix).
  TokMAC = ( AHex{2} ( AColon AHex{2} ){5} | AHex{2} ( ADash AHex{2} ){5}
           | AHex{4} ADot AHex{4} ADot AHex{4} )
           >startToken @endToken;

  # Windows Security Identifier: "S-R-I-S...-RID", e.g.
  # "S-1-5-21-3623811015-3361044348-30300820-1013". '-' is not a UAX#29
  # joiner, so without this a SID shatters into "S" plus one Number token
  # per dash-separated group -- and worse, a well-known SID (3 groups,
  # e.g. "S-1-5-18") and a domain SID (6-7 groups) then differ in *token
  # count*, not just value, so they can't even fuzzy-match the same
  # template. Requires >=3 dash-separated decimal groups after the literal
  # 'S' (revision, identifier authority, and at least one sub-authority) --
  # the minimum any real SID has -- to avoid misfiring on shorter
  # hyphenated tokens that happen to start with a bare "S". Capital 'S'
  # only: the documented SDDL string form is always rendered uppercase.
  SidNum = ADigit{1,15};
  TokSID = ( 0x53 ADash SidNum ( ADash SidNum ){2,} ) >startToken @endToken;

  EmLocal = ( AAlnum | ADot | 0x5F | 0x25 | 0x2B | ADash )+;
  EmLabel = ( AAlnum | ADash )+;
  TokEmail = ( EmLocal AAt EmLabel ( ADot EmLabel )+ ) >startToken @endToken;

  # IPv6, the RFC 4291 text forms (RFC 3986's IPv6address ABNF): 8 groups,
  # or fewer with one "::", the last 32 bits optionally a dotted quad
  # ("::ffff:172.16.1.1"). ':' is a UAX#29 MidLetter joiner and '.' a
  # MidNumLet, so without this an address shatters unevenly -- "45ff:d67a"
  # fuses, "2a00:801" doesn't -- and a run of 2-digit groups is taken by
  # TokClock ("2604:4000:0:d:216:40:47:26" loses "16:40:47" to a
  # Timestamp). Matching the whole address is longer than any of those, so
  # longest match settles it.
  #
  # Three guards on top of the grammar:
  #   - at least 8 bytes: "a::" and "1::1" are WordBreakTest cases that must
  #     split, and every conformance string of hex digits and ':' is <= 4
  #     bytes. Shorter addresses ("::1", "fe80::1") are left to the caller;
  #     none of them is long enough to contain a clock.
  #   - at least one digit: hex-only identifiers such as "Feed::add" or
  #     "Cafe::Bad" (C++/PHP scope syntax) are valid compressed addresses by
  #     grammar alone.
  #   - not 8 groups of exactly 2 hex digits: that is a run of hex pairs --
  #     the tail of netfilter's 14-byte "MAC=" chain, or of a key
  #     fingerprint, once the leading pairs have gone to TokMAC -- and a
  #     real address practically never prints that way.
  # A 6-group MAC and a 3-group clock are not valid addresses (no "::"), so
  # neither can tie with this rule. An unbracketed port after a full
  # 8-group address is left out (a 9th group is invalid), but after a "::"
  # address it reads as one more group -- the text alone can't tell.
  H16  = AHex{1,4};
  H16C = H16 AColon;
  Dec  = ADigit{1,3};
  Ls32 = H16 AColon H16 | Dec ADot Dec ADot Dec ADot Dec;
  DCol = AColon AColon;
  IPv6Addr =                            H16C{6} Ls32
           |                       DCol H16C{5} Ls32
           | ( H16 )?              DCol H16C{4} Ls32
           | ( H16C{0,1} H16 )?    DCol H16C{3} Ls32
           | ( H16C{0,2} H16 )?    DCol H16C{2} Ls32
           | ( H16C{0,3} H16 )?    DCol H16C    Ls32
           | ( H16C{0,4} H16 )?    DCol         Ls32
           | ( H16C{0,5} H16 )?    DCol         H16
           | ( H16C{0,6} H16 )?    DCol;
  #
  # What the grammar can't see is the text after the match, so
  # finishIPv6Token checks it (ipv6End): a match that runs on into a longer
  # group ("fdcd:304b:f1d4::1:6019" in "...::1:60198", an unbracketed
  # 5-digit port) is cut back to the last whole group, and one followed by
  # more colon-separated hex that isn't a port is rejected. A rejected start
  # is rescanned with this rule switched off there (the ipv6Allowed
  # condition), so it segments exactly as it would without IPv6 typing.
  # The text before the match is out of reach: SegmentWords scans one token
  # per call, from the token's first byte.
  HexPairs8 = AHex{2} ( AColon AHex{2} ){7};
  TokIPv6 = ( ( ( IPv6Addr - HexPairs8 ) & ( any{8} any* ) & ( any* ADigit any* ) )
              when ipv6Allowed )
            >startToken @endToken;

  # ---- date / time ------------------------------------------------------
  # Every alternative is >=8 bytes, so none can collide with the UCD
  # WordBreakTest strings, which are all <= 4 chars.
  D2 = ADigit{2};
  D4 = ADigit{4};
  AComma = 0x2C;  ASlash = 0x2F;  APlus = 0x2B;
  Frac = ( ADot | AComma ) ADigit{1,9};
  Zone = ( 0x5A | 0x7A )                              # Z | z
       | ( APlus | ADash ) D2 ( AColon? D2 )?;        # +hh[:mm] / -hhmm
  ClockTime = D2 AColon D2 AColon D2 Frac?;           # HH:MM:SS[.frac]
  IsoSep = 0x54 | 0x74;                               # T | t
  # YYYY-MM-DD, optionally THH:MM:SS[.frac][zone]
  TokISO = ( D4 ADash D2 ADash D2 ( IsoSep ClockTime Zone? )? ) >startToken @endToken;
  # CLF / HAProxy: DD/Mon/YYYY:HH:MM:SS[.frac]
  Mon = "Jan" | "Feb" | "Mar" | "Apr" | "May" | "Jun"
      | "Jul" | "Aug" | "Sep" | "Oct" | "Nov" | "Dec";
  TokCLF = ( ADigit{1,2} ASlash Mon ASlash D4 AColon D2 AColon D2 AColon D2 Frac? )
           >startToken @endToken;
  # bare wall-clock, the syslog/kernel form
  TokClock = ( ClockTime ) >startToken @endToken;


  main := |*
    TokCLF => finishTimestampToken;
    TokISO => finishTimestampToken;
    TokIPv4 => finishIPv4Token;
    TokIPv6 => finishIPv6Token;
    TokUUID => finishUUIDToken;
    TokMAC => finishMACToken;
    TokSID => finishSIDToken;
    TokEmail => finishEmailToken;
    TokClock => finishTimestampToken;
    WordNumeric => finishNumericToken;
    WordHangul => finishHangulToken;
    WordKatakana => finishKatakanaToken;
    Word => finishWordToken;
    WordHan => finishHanToken;
    WordHiragana => finishHiraganaToken;
    WordRegional =>finishNoneToken;
    WordCRLF => finishNoneToken;
    WordCR => finishNoneToken;
    WordLF => finishNoneToken;
    WordNL => finishNoneToken;
    WordExt => finishNoneToken;
    Other => finishNoneToken;
  *|;

    write init;
    write exec;
  }%%

  if cs < s_first_final {
    return val, types, totalConsumed, ParseError
  }

  return val, types, totalConsumed, nil
}
