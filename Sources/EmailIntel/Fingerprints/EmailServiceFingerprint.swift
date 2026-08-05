import Foundation

public struct FingerprintSignals: Codable, Sendable {
    public let spfIncludes: [String]
    public let dkimSelectors: [String]
    public let mxPatterns: [String]
    public let txtVerification: [String]

    public init(
        spfIncludes: [String] = [],
        dkimSelectors: [String] = [],
        mxPatterns: [String] = [],
        txtVerification: [String] = []
    ) {
        self.spfIncludes = spfIncludes
        self.dkimSelectors = dkimSelectors
        self.mxPatterns = mxPatterns
        self.txtVerification = txtVerification
    }

    enum CodingKeys: String, CodingKey {
        case spfIncludes, dkimSelectors, mxPatterns, txtVerification
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.spfIncludes = (try? container.decode([String].self, forKey: .spfIncludes)) ?? []
        self.dkimSelectors = (try? container.decode([String].self, forKey: .dkimSelectors)) ?? []
        self.mxPatterns = (try? container.decode([String].self, forKey: .mxPatterns)) ?? []
        self.txtVerification = (try? container.decode([String].self, forKey: .txtVerification)) ?? []
    }
}

public struct EmailServiceFingerprint: Codable, Sendable {
    public let id: String
    public let name: String
    public let category: EmailServiceCategory
    public let signals: FingerprintSignals
}
