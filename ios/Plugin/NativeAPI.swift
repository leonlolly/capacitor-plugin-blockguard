import Foundation

@objc public class NativeAPI: NSObject {
    @objc public func echo(_ value: String) -> String {
        print(value)
        return value
    }
}
