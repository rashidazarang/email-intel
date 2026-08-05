import Foundation

public enum EmailServiceCategory: String, Codable, Sendable {
    case mailboxProvider
    case transactional
    case marketing
    case security
    case verification
    case other
}

public struct EmailProvider: Codable, Sendable {
    public let id: String
    public let name: String
    public let category: EmailServiceCategory
    public let confidence: Int
    public let matchedSignals: [String]

    public init(
        id: String,
        name: String,
        category: EmailServiceCategory,
        confidence: Int,
        matchedSignals: [String]
    ) {
        self.id = id
        self.name = name
        self.category = category
        self.confidence = min(max(confidence, 0), 100)
        self.matchedSignals = matchedSignals
    }
}
