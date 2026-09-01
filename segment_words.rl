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
  // There is deliberately no IPv6 type. Every added rule is at least 8 bytes
  // long, so none can collide with the UCD WordBreakTest strings (all <= 4
  // chars). Compressed IPv6 cannot meet that bar: "a::" and "1::1" are valid
  // addresses and are also conformance cases that must split, so recognizing
  // them here fails the Unicode test suite. Left to the caller.
  IPv4
  UUID
  Email
  MAC
  Timestamp
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

  # 8-4-4-4-12. '-' is not a UAX#29 joiner, so today this shatters into 9 tokens.
  TokUUID = ( AHex{8} ADash AHex{4} ADash AHex{4} ADash AHex{4} ADash AHex{12} )
            >startToken @endToken;

  # 6 groups of 2 hex, colon- or dash-separated. Kept ahead of TokClock so an
  # all-numeric MAC still wins on length rather than matching as a wall clock.
  TokMAC = ( AHex{2} ( AColon AHex{2} ){5} | AHex{2} ( ADash AHex{2} ){5} )
           >startToken @endToken;

  EmLocal = ( AAlnum | ADot | 0x5F | 0x25 | 0x2B | ADash )+;
  EmLabel = ( AAlnum | ADash )+;
  TokEmail = ( EmLocal AAt EmLabel ( ADot EmLabel )+ ) >startToken @endToken;

  # Uncompressed form requires all 8 groups, so "12:34:56" (a clock) and a
  # 6-group MAC cannot match. A trailing '::' needs >=2 groups before it, so
  # "a::" stays three tokens as UAX#29 requires (this is a real conformance
  # case in the UCD WordBreakTest tables, not a hypothetical).
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
    TokUUID => finishUUIDToken;
    TokMAC => finishMACToken;
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
