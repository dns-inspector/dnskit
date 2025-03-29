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

import XCTest
@testable import DNSKit

final class NameTests: XCTestCase {
    func testEncodeName() throws {
        let cases = [
            ("www.example.com", "03777777076578616d706c6503636f6d00"),
            ("www.example.com.", "03777777076578616d706c6503636f6d00"),
            (".", "00"),
        ]

        for testCase in cases {
            let encodedName = try Name.stringToName(testCase.0)
            XCTAssertEqual(encodedName.hexEncodedString(), testCase.1)
        }
    }

    func testEncodeNameError() {
        do {
            _ = try Name.stringToName("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            XCTFail("No exception thrown for invalid name")
        } catch {
            //
        }
    }

    func testReadUncompressedName() throws {
        let nameLiteral: [UInt8] = [ 0x03, 0x64, 0x6e, 0x73, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x00 ]
        let data = Data(bytes: nameLiteral, count: nameLiteral.count)
        let (name, dataOffset) = try Name.readName(data, startOffset: 0)
        XCTAssertEqual(name, "dns.google.")
        XCTAssertEqual(dataOffset, 12)
    }

    func testReadCompressedName() throws {
        let nameLiteral: [UInt8] = [ 0x03, 0x64, 0x6e, 0x73, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x00, 0xc0, 0x00 ]
        let data = Data(bytes: nameLiteral, count: nameLiteral.count)
        let (name, dataOffset) = try Name.readName(data, startOffset: 12)
        XCTAssertEqual(name, "dns.google.")
        XCTAssertEqual(dataOffset, 14)
    }

    func testReadRoot() throws {
        let nameLiteral: [UInt8] = [ 0x00 ]
        let data = Data(bytes: nameLiteral, count: nameLiteral.count)
        let (name, dataOffset) = try Name.readName(data, startOffset: 0)
        XCTAssertEqual(name, ".")
        XCTAssertEqual(dataOffset, 1)
    }

    func testCatchRecursiveCompressionPointer() throws {
        do {
            let nameLiteral: [UInt8] = [ 0xc0, 0x00, 0xc0, 0x00 ]
            let data = Data(bytes: nameLiteral, count: nameLiteral.count)
            _ = try Name.readName(data, startOffset: 2)
            XCTFail("No exception thrown when one expected")
        } catch {
            //
        }
    }

    func testCatchInvalidCharactersInName() throws {
        do {
            let nameLiteral: [UInt8] = [ 0x04, 0x64, 0x6e, 0x73, 0x2e, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x00 ]
            let data = Data(bytes: nameLiteral, count: nameLiteral.count)
            _ = try Name.readName(data, startOffset: 0)
            XCTFail("No exception thrown when one expected")
        } catch {
            //
        }
    }

    func testCatchInvalidSegmentLength() throws {
        do {
            let nameLiteral: [UInt8] = [ 0x03, 0x64, 0x6e, 0x73, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x16 ]
            let data = Data(bytes: nameLiteral, count: nameLiteral.count)
            _ = try Name.readName(data, startOffset: 0)
            XCTFail("No exception thrown when one expected")
        } catch {
            //
        }
    }

    func testCatchInvalidPointerOffset() throws {
        do {
            let nameLiteral: [UInt8] = [ 0xc0, 0x16 ]
            let data = Data(bytes: nameLiteral, count: nameLiteral.count)
            _ = try Name.readName(data, startOffset: 0)
            XCTFail("No exception thrown when one expected")
        } catch {
            //
        }
    }

    func testCatchInvalidPointerDestinationOffset() throws {
        do {
            let nameLiteral: [UInt8] = [ 0xc0, 0x16, 0xc0, 0x00 ]
            let data = Data(bytes: nameLiteral, count: nameLiteral.count)
            _ = try Name.readName(data, startOffset: 0)
            XCTFail("No exception thrown when one expected")
        } catch {
            //
        }
    }

    func testCatchInvalidStartIndexUnderflow() throws {
        do {
            let nameLiteral: [UInt8] = [ 0x03, 0x64, 0x6e, 0x73, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x16 ]
            let data = Data(bytes: nameLiteral, count: nameLiteral.count)
            _ = try Name.readName(data, startOffset: -1)
            XCTFail("No exception thrown when one expected")
        } catch {
            //
        }
    }

    func testCatchInvalidStartIndexOverflow() throws {
        do {
            let nameLiteral: [UInt8] = [ 0x03, 0x64, 0x6e, 0x73, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x16 ]
            let data = Data(bytes: nameLiteral, count: nameLiteral.count)
            _ = try Name.readName(data, startOffset: 16)
            XCTFail("No exception thrown when one expected")
        } catch {
            //
        }
    }

    func testSplitName() throws {
        var parts = Name.splitName("www.example.com")

        XCTAssertEqual(parts.count, 3)
        XCTAssertEqual(parts[0], "www")
        XCTAssertEqual(parts[1], "example")
        XCTAssertEqual(parts[2], "com")

        parts = Name.splitName("www.example.com.")

        XCTAssertEqual(parts.count, 3)
        XCTAssertEqual(parts[0], "www")
        XCTAssertEqual(parts[1], "example")
        XCTAssertEqual(parts[2], "com")

        parts = Name.splitName(".")

        XCTAssertEqual(parts.count, 0)
    }

    func testParentNames() throws {
        let parents = Name.parentNames(from: "foo.example.com.")
        XCTAssertEqual(parents.count, 3)
        XCTAssertEqual(parents[0], "example.com.")
        XCTAssertEqual(parents[1], "com.")
        XCTAssertEqual(parents[2], ".")
    }
}
