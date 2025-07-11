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
import Testing
@testable import DNSKit

@Suite("IP Address") struct IPAddressTests {
    @Test func v4ToArpaName() async throws {
        let name = try IPAddress.v4ToArpaName("8.8.4.4")
        #expect(name == "4.4.8.8.in-addr.arpa")
    }
    
    @Test func v6ToArpaName() async throws {
        let name = try IPAddress.v6ToArpaName("2001:db8::567:89ab")
        #expect(name == "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa")
    }
}
