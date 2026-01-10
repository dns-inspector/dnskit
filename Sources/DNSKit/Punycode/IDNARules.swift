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

import Foundation
import IdnaRules

/// This class provides methods for finding and interacting with IDNA rules.
///
/// During development we found that generating the IDNA rules as Swift code caused a memory exhaustion bug with the Swift frontend,
/// as such, and since we're working with entirely static data, all of the rules are defined in a C library thats imported here.
/// This class just provides a bridge between the two for conveience.
internal final class IDNARules {
    /// Return a list of possible rules that may match the given codepoint.
    ///
    /// Rule lists are internally organized in a way that groups rules together based on their codepoint neighbours, therefor
    /// this method may return a list of rules that do not apply to the given codepoint. You must filter these rules later using
    /// the ``IDNARules.ruleAppliesTo(rule:codepoint:)`` method
    /// - Parameter codepoint: The codepoint to use when looking for possible rules
    /// - Returns: A list of rules, which may be empty.
    public static func getRules(for codepoint: UInt32) -> [IDNARule] {
        var ruleCount = Int(0)
        guard let ptr = IdnaRules.find_idna_rules(codepoint, &ruleCount) else {
            return []
        }
        if ruleCount <= 0 {
            return []
        }

        return ptr.withMemoryRebound(to: IDNARule.self, capacity: ruleCount) {
            Array(UnsafeBufferPointer(start: $0, count: ruleCount))
        }
    }

    /// Checks if the  rule applies to the codepoint
    /// - Parameters:
    ///   - rule: The rule
    ///   - codepoint: The codepoint
    /// - Returns: True if the rule applies to this codepoint
    public static func ruleAppliesTo(rule: IDNARule, codepoint: UInt32) -> Bool {
        return codepoint >= rule.codepointStart && codepoint <= rule.codepointEnd
    }

    /// Extracts the list of replacement codepoints from this rule
    /// - Parameter rule: The rule
    /// - Returns: A list of unicode scalars (as Uint32 values) to replace, or an empty array.
    public static func getRuleReplacement(rule: IDNARule) -> [UInt32] {
        if rule.replace_len == 0 {
            return []
        }
        return rule.replace_with.withMemoryRebound(to: UInt32.self, capacity: rule.replace_len) {
            Array(UnsafeBufferPointer(start: $0, count: rule.replace_len))
        }
    }
}
