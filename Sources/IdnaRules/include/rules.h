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

#include <stdint.h>

typedef enum: uint8_t {
    idnarule_action_ignored,
    idnarule_action_mapped,
    idnarule_action_disallowed,
} idnarule_action;

typedef struct {
  uint32_t codepointStart;
  uint32_t codepointEnd;
  idnarule_action action;
  size_t replace_len;
  const uint32_t *replace_with;
} IDNARule;

/// Return a list of IDNA rules that are relevant to the given codepoint. The individual rules may not apply to the codepoint, so you must check that the codepoint falls within the start and end bounds.
/// The returned array must not be freed.
/// - Parameters:
///   - codepoint: The codepoint to use as a query
///   - rule_count: Will be populated with the number of rules in the returned array. If no matching rules are found, will be populated with -1.
/// - Returns: A pointer to an static array that contains rules, or NULL.
extern const IDNARule* find_idna_rules(uint32_t codepoint, size_t* rule_count);
