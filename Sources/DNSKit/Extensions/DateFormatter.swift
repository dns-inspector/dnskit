import Foundation

internal extension DateFormatter {
    convenience init(format: String) {
        self.init()
        self.dateFormat = format
    }

    static func iso8601() -> DateFormatter {
        return DateFormatter(format: "yyyyMMdd'T'HHmmssZ")
    }
}
