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

/// Describes the record data for a LOC record. LOC records represent a WGS 84 position.
public struct LOCRecordData: RecordData {
    /// The size or area of the location in RFC1867 form.
    public let size: UInt8

    /// The size or area of the location in meters.
    public let sizeMeters: Double

    /// The amount of horizontal precision or accuracy of the location in RFC1867 form.
    public let horizontalPrecision: UInt8

    /// The amount of horizontal precision or accuracy of the location in meters.
    public let horizontalPrecisionMeters: Double

    /// The amount of vertical precision or accuracy of the location in RFC1867 form.
    public let verticalPrecision: UInt8

    /// The amount of vertical precision or accuracy of the location in meters.
    public let verticalPrecisionMeters: Double

    /// The latitude of the center of the location in RFC1867 form.
    public let latitude: UInt32

    /// The longitude of the center of the location in RFC1867 form.
    public let longitude: UInt32

    /// The altitude of the location in RFC1867 form.
    public let altitude: UInt32

    /// The altitude of the location in meters.
    public let altitudeMeters: Double

    internal init(messageData: Data, startOffset: Int) throws {
        let dataArray = Array(messageData)

        let version = dataArray[startOffset]
        if version != 0 {
            throw DNSKitError.invalidData("Unsupported LOC record version \(version)")
        }

        self.size = dataArray[startOffset+1]
        self.sizeMeters = LOCRecordData.deserializeSize(b: self.size)
        self.horizontalPrecision = dataArray[startOffset+2]
        self.horizontalPrecisionMeters = LOCRecordData.deserializeSize(b: self.horizontalPrecision)
        self.verticalPrecision = dataArray[startOffset+3]
        self.verticalPrecisionMeters = LOCRecordData.deserializeSize(b: self.verticalPrecision)

        self.latitude = messageData.withUnsafeBytes { data in
            return data.loadUnaligned(fromByteOffset: startOffset+4, as: UInt32.self).bigEndian
        }
        self.longitude = messageData.withUnsafeBytes { data in
            return data.loadUnaligned(fromByteOffset: startOffset+8, as: UInt32.self).bigEndian
        }
        self.altitude = messageData.withUnsafeBytes { data in
            return data.loadUnaligned(fromByteOffset: startOffset+12, as: UInt32.self).bigEndian
        }
        self.altitudeMeters = (Double(self.altitude) - 10000000)/100.0
    }

    // ref: RFC1867
    internal static func deserializeSize(b: UInt8) -> Double {
        var size = Double((b & 0xF0) >> 4)
        var exponent = (b & 0x0F)
        while exponent != 0 {
            size *= 10
            exponent -= 1
        }
        return Double(size / 100)
    }

    internal static func deserializeAngle(v: UInt32, longitude: Bool, includeUnits: Bool = true) -> String {
        var angle = v
        var direction: String

        if angle < 0x80000000 {
            angle = 0x80000000 - angle
            direction = longitude ? "W" : "S"
        } else {
            angle -= 0x80000000
            direction = longitude ? "E" : "N"
        }

        if longitude ? (angle > 648000000) : (angle > 324000000) {
            return "Error: angle value out of range"
        }

        let tsecs = angle % 1000
        angle /= 1000
        let secs = angle % 60
        angle /= 60
        let minutes = angle % 60
        let degrees = angle / 60

        if !includeUnits {
            return String(format: "%u %u %u.%u %@", degrees, minutes, secs, tsecs, direction)
        }

        return String(format: "%02u deg %02u min %02u.%03u sec %@", degrees, minutes, secs, tsecs, direction)
    }

    /// Return a formatted string with a Degrees, Minutes, Seconds (DMS) representation of the latitude (1st) and longitude (2nd) values.
    public func degrees() -> (String, String) {
        return (LOCRecordData.deserializeAngle(v: self.latitude, longitude: false), LOCRecordData.deserializeAngle(v: self.longitude, longitude: true))
    }

    public var description: String {
        let latitude = LOCRecordData.deserializeAngle(v: self.latitude, longitude: false, includeUnits: false)
        let longitude = LOCRecordData.deserializeAngle(v: self.longitude, longitude: true, includeUnits: false)
        let altitude = String(format: "%.2fm", self.altitudeMeters)
        let size = String(format: "%.2fm", self.sizeMeters)
        let horizontalPrecision = String(format: "%.2fm", self.horizontalPrecisionMeters)
        let verticalPrecision = String(format: "%.2fm", self.verticalPrecisionMeters)
        return "\(latitude) \(longitude) \(altitude) \(size) \(horizontalPrecision) \(verticalPrecision)"
    }
}
