import Foundation

internal extension DispatchTime {
    func adding(seconds: UInt8) -> DispatchTime {
        if #available(iOS 13, macOS 10.15, *) {
            return DispatchTime.now().advanced(by: DispatchTimeInterval.seconds(Int(seconds)))
        } else {
            let timeout = DispatchTime.now().uptimeNanoseconds + UInt64(seconds) * NSEC_PER_SEC
            return DispatchTime(uptimeNanoseconds: timeout)
        }
    }
}
