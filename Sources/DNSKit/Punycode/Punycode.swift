// DNSKit
// Copyright (C) Ian Spence and other DNSKit Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// The logic here is largely influenced by https://gitlab.com/golang-commonmark/puny and https://www.rfc-editor.org/rfc/rfc3492.html
// and has been adapted to work with Swift.

import Foundation
import IdnaRules

/// Provides means to encode a UTF-8 string to a IDNA-compatible ASCII string using Punycode encoding
public struct Punycode: Sendable {
    private static let base: Int32 = 36
    private static let baseMinusTMin = base - 1
    private static let tMax: Int32 = 26
    private static let skew: Int32 = 38

    /// Encode the given domain name to an IDNA-compatible ASCII string using Punycode encoding.
    /// - Parameter name: The original name
    /// - Returns: An encoded name, gauranteed to be an ASCII string.
    public static func toASCII(_ name: String) throws -> String {
        let labels = splitLabels(try applyRules(name))
        var encodedLabels: [String] = []
        for label in labels {
            if label.unicodeScalars.allSatisfy({ $0.isASCII }) {
                encodedLabels.append(label)
                continue
            }

            encodedLabels.append("xn--" + (try encode(label)))
        }

        return encodedLabels.joined(separator: ".")
    }

    // Readers note: when I say "Character" below I am refering to a single UTF-8 scalar / codepoint ('rune' in go).
    // I am not referring to the Swift 'Character' type, as that can refer to multiple UTF-8 codepoints
    private static func encode(_ label: String) throws -> String {
        var bias: Int32 = 72
        var delta: Int32 = 0
        var n: Int32 = 128

        var output: [Unicode.Scalar] = []
        var scalarsToEncode = 0

        // Start by removing all non-ascii characters and counting how many characters were removed
        for scalar in label.unicodeScalars {
            if !scalar.isASCII {
                scalarsToEncode += 1
                continue
            }
            output.append(scalar)
        }

        if scalarsToEncode == 0 {
            fatalError("encode called with a string that only contains ASCII characters")
        }

        let basicLength = output.count
        var encodedScalarCount = basicLength

        // IDNA appends the non-ASCII characters and their positioning data at the end of the name.
        // If the label has any ASCII characters, a dash is used to denote the end of the ASCII portion of the label and the start of the punycode.
        if basicLength > 0 {
            output.append("-")
        }

        // Roughly described, punycode describes a means to encode Unicode characters as a base-36 number.
        // These numbers include the position of the character and the scalar value itself.
        // Individual characters may result in multiple base-36 values (that is, a-z 0-9 - NOT hex).
        // As each character is encoded, the algorithm is adapted to bias similar characters,
        // resulting in smaller (therefor shorter) numbers.
        while scalarsToEncode > 0 {
            // We sort the characters to encode by smallest first
            var m = Int32.max
            for scalar in label.unicodeScalars {
                if scalar.value >= n && scalar.value < m {
                    m = Int32(scalar.value)
                }
            }

            let encodedScalarCountPlusOne = Int32(encodedScalarCount + 1)
            if m-n > (Int32.max-delta)/encodedScalarCountPlusOne {
                throw DNSKitError.invalidData("Overflow unicode scalar")
            }

            delta += (m-n) * encodedScalarCountPlusOne
            n = m

            // https://www.rfc-editor.org/rfc/rfc3492.html#section-6.3
            for scalar in label.unicodeScalars {
                if scalar.value < n {
                    delta += 1
                    if delta < 0 {
                        throw DNSKitError.invalidData("Overflow unicode scalar")
                    }
                    continue
                }
                if scalar.value > n {
                    continue
                }
                var q = delta

                var k = base
                while true {
                    var t = k - bias
                    if t < 1 {
                        t = 1
                    } else if t > tMax {
                        t = tMax
                    }
                    if q < t {
                        break
                    }

                    let qMinusT = q - t
                    let baseMinusT = base - t
                    let digit = t+qMinusT%baseMinusT
                    let basic = digitToScalar(digit)
                    output.append(basic)
                    q = qMinusT / baseMinusT
                    k += base
                }

                let basic = digitToScalar(q)
                output.append(basic)
                bias = adaptBias(delta, encodedScalarCountPlusOne, encodedScalarCount == basicLength)
                delta = 0
                encodedScalarCount += 1
                scalarsToEncode -= 1
            }
            delta += 1
            n += 1
        }

        return String(String.UnicodeScalarView(output))
    }

    private static func digitToScalar(_ digit: Int32) -> Unicode.Scalar {
        if digit >= 0 && digit <= 25 {
            return .init(UInt8(digit) + 97) // a-z
        }
        if digit >= 26 && digit <= 35 {
            return .init(UInt8(digit) - 26 + 48) // 0-9
        }
        fatalError()
    }

    // https://www.rfc-editor.org/rfc/rfc3492.html#section-6.1
    private static func adaptBias(_ d: Int32, _ scalarCount: Int32, _ firstPass: Bool) -> Int32 {
        var delta = firstPass ? d / 700 : d / 2

        delta += delta / scalarCount
        var k: Int32 = 0

        while delta > baseMinusTMin*tMax/2 {
            delta /= baseMinusTMin
            k += base
        }

        return k + (baseMinusTMin+1) * delta / (delta + skew)
    }

    private static func splitLabels(_ s: String) -> [String] {
        var name = s
        name = name.replacingOccurrences(of: "。", with: ".") // IDEOGRAPHIC FULL STOP
        name = name.replacingOccurrences(of: "．", with: ".") // FULLWIDTH FULL STOP
        name = name.replacingOccurrences(of: "｡", with: ".") // HALFWIDTH IDEOGRAPHIC FULL STOP
        return name.components(separatedBy: ".")
    }

    private static func applyRules(_ s: String) throws -> String {
        var output: [Unicode.Scalar] = []
        for r in s.unicodeScalars {
            let rules = IDNARules.getRules(for: r.value)
            if rules.isEmpty {
                output.append(r)
                continue
            }

            var ruleApplied = false
            for rule in rules where IDNARules.ruleAppliesTo(rule: rule, codepoint: r.value) {
                if rule.action == idnarule_action_ignored {
                    ruleApplied = true
                    break
                }

                if rule.action == idnarule_action_mapped {
                    for replacement in IDNARules.getRuleReplacement(rule: rule) {
                        output.append(.init(replacement)!)
                    }
                    ruleApplied = true
                    break
                }
            }

            if !ruleApplied {
                output.append(r)
            }
        }

        let name = String(String.UnicodeScalarView(output))
        for r in name.unicodeScalars {
            for rule in IDNARules.getRules(for: r.value) where IDNARules.ruleAppliesTo(rule: rule, codepoint: r.value) {
                if rule.action == idnarule_action_disallowed {
                    throw DNSKitError.invalidData("Illegal character '\(r)' in DNS name")
                }
            }
        }

        return name
    }
}
