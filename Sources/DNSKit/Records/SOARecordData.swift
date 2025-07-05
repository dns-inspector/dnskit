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

/// Describes the record data for an SOA record
public struct SOARecordData: RecordData, CompressibleRecordData {
    /// Primary nameserver
    public let mname: String
    /// Administrator email
    public let rname: String
    /// Zone serial
    public let serial: UInt32
    /// Number of seconds to wait between polling for zone changes
    public let refresh: Int32
    /// Number of seconds to wait if the primary nameserver did not respond
    public let retry: Int32
    /// Number of seconds to wait before giving up if the primary nameserver does not respond
    public let expire: Int32
    /// Negative response caching TTL
    public let minimum: UInt32

    internal var uncompressedRecordData: Data

    internal init(messageData: Data, startOffset: Int) throws {
        let (mname, rnameOffset) = try Name.readName(messageData, startOffset: startOffset)
        var (rname, serialOffset) = try Name.readName(messageData, startOffset: rnameOffset)
        let (serial, refresh, retry, expire, minimum) = messageData.withUnsafeBytes { data in
            var offset = serialOffset

            let serial = data.loadUnaligned(fromByteOffset: offset, as: UInt32.self).bigEndian
            offset += 4

            let refresh = data.loadUnaligned(fromByteOffset: offset, as: Int32.self).bigEndian
            offset += 4

            let retry = data.loadUnaligned(fromByteOffset: offset, as: Int32.self).bigEndian
            offset += 4

            let expire = data.loadUnaligned(fromByteOffset: offset, as: Int32.self).bigEndian
            offset += 4

            let minimum = data.loadUnaligned(fromByteOffset: offset, as: UInt32.self).bigEndian

            return (serial, refresh, retry, expire, minimum)
        }

        self.uncompressedRecordData = Data()
        self.uncompressedRecordData.append(try Name.stringToName(mname))
        self.uncompressedRecordData.append(try Name.stringToName(rname))
        self.uncompressedRecordData.append(messageData.suffix(from: serialOffset).prefix(4*5))

        if let r = rname.range(of: ".") {
            rname = rname.replacingCharacters(in: r, with: "@")
        }

        self.mname = mname
        self.rname = rname
        self.serial = serial
        self.refresh = refresh
        self.retry = retry
        self.expire = expire
        self.minimum = minimum
    }

    public var description: String {
        return "\(self.mname) \(self.rname) \(self.serial) \(self.refresh) \(self.retry) \(self.expire) \(self.minimum)"
    }
}
