"""
DNSKit
Copyright (C) Ian Spence and other DNSKit Contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
from dataclasses import dataclass
import http.client
import os
import sys
import io

@dataclass
class Rule:
    cpLow: str
    cpHigh: str
    action: str
    mapping: list[str]

    def toC(self, replace_prefix: str) -> str:
        start = self.cpLow
        end = self.cpHigh
        status = "idnarule_action_%s" % self.action
        mapping = "NULL"
        if len(rule.mapping) > 0:
            mapping = "%s_replace" % replace_prefix

        return "{ %s, %s, %s, %d, %s }" % (start, end, status, len(rule.mapping), mapping)

@dataclass
class Page:
    num: int
    cpLow: str
    cpHigh: str
    rules: list[Rule]

def parseRules():
    rules = list[Rule]()

    connection = http.client.HTTPSConnection("www.unicode.org")
    connection.request("GET", "/Public/idna/latest/IdnaMappingTable.txt")
    response = connection.getresponse()
    text_stream = io.TextIOWrapper(response, encoding="utf-8")
    line_n = 0
    for line in text_stream:
        line_n += 1
        line = line.rstrip()
        if not line:
            continue

        if line[0] == "#" or line == "":
            continue

        # Line structure:
        # Num   Field              Description
        # 0     Code point(s)      Hex value or range of values.
        # 1     Status             valid, ignored, mapped, deviation, or disallowed
        # 2     Mapping            Hex value(s). Only present if the Status is ignored, mapped, or
        #                          deviation.
        # (we don't care about the remaining fields)

        comment = ""

        parts = line.split('#')
        if len(parts) > 1:
            comment = parts[len(parts)-1]
            line = line.replace("# " + comment, "")
            line = line.replace("#" + comment, "")
        
        parts = line.split(';')
        if len(parts) < 2:
            print("Syntax error on line %d: too few columns" % (line_n))
            sys.exit(1)

        codePoints = parts[0].strip().split("..")
        if len(codePoints) == 1:
            codePoints.append(codePoints[0])

        cpLow = "0x"+codePoints[0]
        cpHigh = "0x"+codePoints[1]

        status = parts[1].strip()
        if status != "valid" and status != "ignored" and status != "mapped" and status != "deviation" and status != "disallowed":
            print("Syntax error on line %d: invalid satatus '%s'" % (line_n, status))
            sys.exit(1)

        if status == "valid" or status == "deviation":
            continue

        mapping = list[int]()
        if len(parts) >= 3:
            for m in parts[2].split(" "):
                m = m.strip()
                if m == "":
                    continue
                mapping.append("0x" + m)

        rules.append(Rule(cpLow, cpHigh, status, mapping))

    return rules

def makePages(rules: list[Rule]) -> list[Page]:
    # Pages are collections of rules who's codepoints are as close together as possible

    pages = list[Page]()

    rule_group = list[Rule]()
    page_num = 1
    for rule in rules:
        icpLow = int(rule.cpLow, 0)
        icpHigh = int(rule.cpHigh, 0)

        # some rules span many codepoints
        if icpLow >> 8 != icpHigh >> 8:
            if len(rule_group) > 0:
                pages.append(Page(page_num, rule_group[0].cpLow, rule_group[-1].cpHigh, rule_group))
                page_num += 1
            pages.append(Page(page_num, rule.cpLow, rule.cpHigh, [rule]))
            page_num += 1
            rule_group = list[Rule]()
            continue

        if len(rule_group) == 0:
            rule_group.append(rule)
        else:
            if icpLow >> 8 == int(rule_group[-1].cpLow, 0) >> 8:
                rule_group.append(rule)
            else:
                pages.append(Page(page_num, rule_group[0].cpLow, rule_group[-1].cpHigh, rule_group))
                page_num += 1
                rule_group = [rule]
    pages.append(Page(page_num, rule_group[0].cpLow, rule_group[-1].cpHigh, rule_group))
    page_num += 1
    return pages

pages = makePages(parseRules())

with open('rules.c', 'w') as file:
    file.write("""// DNSKit
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

// DO NOT EDIT THIS FILE
// This file is dynamically generated using the update_rules.py script
// The information in this file is sourced from
// https://www.unicode.org/Public/idna/latest/IdnaMappingTable.txt

#include "rules.h"

""")
    for page in pages:
        i = 0
        for rule in page.rules:
            if len(rule.mapping) > 0:
                file.write("const uint32_t page_%d_rule_%d_replace[%d] = {%s};\n" % (page.num, i, len(rule.mapping), ", ".join(rule.mapping)))
            i += 1

        file.write("const size_t page_%d_rule_count = %d;\n" % (page.num, len(page.rules)))
        file.write("const IDNARule page_%d_rules[] = {\n" % page.num)
        i = 0
        for rule in page.rules:
            file.write("  %s,\n" % rule.toC("page_%d_rule_%d" % (page.num, i)))
            i += 1
        file.write("};\n")

    file.write("\nconst IDNARule* find_idna_rules(uint32_t codepoint, size_t* rule_count) {\n")
    file.write("  switch (codepoint >> 8) {\n")
    for page in pages:
        if int(page.cpLow, 0) >> 8 != int(page.cpHigh, 0) >> 8:
            continue
        key = hex(int(page.cpLow, 0) >> 8)
        file.write("    case %s: {\n" % key)
        file.write("      *rule_count = page_%d_rule_count;\n" % page.num)
        file.write("      return (const IDNARule*)page_%d_rules;\n" % page.num)
        file.write("    }\n")
    file.write("  }\n\n")
    for page in pages:
        if int(page.cpLow, 0) >> 8 == int(page.cpHigh, 0) >> 8:
            continue

        file.write("  if (codepoint >= %s && codepoint <= %s) {\n" % (page.cpLow, page.cpHigh))
        file.write("    *rule_count = page_%d_rule_count;\n" % page.num)
        file.write("    return (const IDNARule*)page_%d_rules;\n" % page.num)
        file.write("  }\n")
    
    file.write("\n  *rule_count = -1;\n")
    file.write("  return NULL;\n")
    file.write("}\n")