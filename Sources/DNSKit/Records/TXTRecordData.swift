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

/// Describes the record data for a TXT record
public struct TXTRecordData: RecordData {
    /// The record text
    public let text: String

    internal init(recordData: Data) throws {
        // TXT RDATA format is a collection of one or more strings, which are: length (uint8) + data
        // No encoding is defined, so we'll assume UTF-8 and throw caution to the wind.

        var moreToRead = true
        var offset = Int(0)

        var textData = Data()

        while moreToRead {
            let length = recordData.withUnsafeBytes {
                return $0.loadUnaligned(fromByteOffset: offset, as: UInt8.self)
            }
            print("Reading \(length)B of data")
            if length == 0 {
                print("Pack it up, we're done here")
                moreToRead = false
                break
            }
            if offset+Int(length) > recordData.count {
                throw DNSKitError.invalidData("Invalid length value in TXT RDATA")
            }

            offset += 1
            let data = recordData.subdata(in: offset..<offset+Int(length))
            print("Data: \(data.hexEncodedString())")
            textData.append(data)
            offset += Int(length)

            if (recordData.count - 1) <= offset {
                moreToRead = false
            }
        }

        guard let text = String(data: textData, encoding: .utf8) else {
            throw DNSKitError.invalidData("Unable to decode TXT RDATA as UTF8 bytes")
        }
        self.text = text
    }

    public var description: String {
        return self.text
    }
}
