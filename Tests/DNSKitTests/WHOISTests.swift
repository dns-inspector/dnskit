// DNSKit
// Copyright (C) 2024 Ian Spence
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

import XCTest
@testable import DNSKit

final class WHOISTests: XCTestCase {
    func getLookupHostForDomain(_ input: String, expectedServer: String, expectedBare: String) {
        let (actualServer, actualBare) = WHOIS.getLookupHost(for: input)

        XCTAssertNotNil(actualServer)
        XCTAssertNotNil(actualBare)
        XCTAssertEqual(expectedServer, actualServer)
        XCTAssertEqual(expectedBare, actualBare)
    }

    func testGetLookupHostForDomain() {
        getLookupHostForDomain("example.com", expectedServer: "whois.verisign-grs.com", expectedBare: "example.com")
        getLookupHostForDomain("example.example.example.com", expectedServer: "whois.verisign-grs.com", expectedBare: "example.com")
        getLookupHostForDomain("example.cn.com", expectedServer: "whois.centralnic.net", expectedBare: "example.cn.com")
        getLookupHostForDomain("example.app", expectedServer: "whois.nic.app", expectedBare: "example.app")
        getLookupHostForDomain("example.example.example.app", expectedServer: "whois.nic.app", expectedBare: "example.app")

        // lmao please im begging you somebody register acab as a gtld
        let (server, bare) = WHOIS.getLookupHost(for: "blm.acab")
        XCTAssertNil(server)
        XCTAssertNil(bare)
    }

    func testWHOISLookup() async throws {
        let result = try await WHOIS.lookup("example.com")
        XCTAssertTrue(result.count > 0)
    }
}
