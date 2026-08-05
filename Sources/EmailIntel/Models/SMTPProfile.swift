import Foundation

public struct SMTPProfile: Codable, Sendable {
    public let banner: String?
    public let ehloExtensions: [String]
    public let starttlsSupported: Bool
    public let tlsVersion: String?

    public init(
        banner: String?,
        ehloExtensions: [String],
        starttlsSupported: Bool,
        tlsVersion: String?
    ) {
        self.banner = banner
        self.ehloExtensions = ehloExtensions
        self.starttlsSupported = starttlsSupported
        self.tlsVersion = tlsVersion
    }
}
