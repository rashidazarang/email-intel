import Foundation

public struct IntelligenceSummary: Codable, Sendable {
    public let mailboxProviders: [String]
    public let transactionalServices: [String]
    public let marketingServices: [String]
    public let verificationRecords: [String]
    public let totalServices: Int
    public let securityPosture: String

    public init(
        mailboxProviders: [String],
        transactionalServices: [String],
        marketingServices: [String],
        verificationRecords: [String],
        totalServices: Int,
        securityPosture: String
    ) {
        self.mailboxProviders = mailboxProviders
        self.transactionalServices = transactionalServices
        self.marketingServices = marketingServices
        self.verificationRecords = verificationRecords
        self.totalServices = totalServices
        self.securityPosture = securityPosture
    }
}

public struct EmailIntelligence: Codable, Sendable {
    public let domain: String
    public let security: SecurityScore
    public let providers: [EmailProvider]
    public let dns: DNSProfile
    public let smtp: SMTPProfile?
    public let summary: IntelligenceSummary
    public let classification: DomainClassification?

    public init(
        domain: String,
        security: SecurityScore,
        providers: [EmailProvider],
        dns: DNSProfile,
        smtp: SMTPProfile?,
        summary: IntelligenceSummary,
        classification: DomainClassification? = nil
    ) {
        self.domain = domain
        self.security = security
        self.providers = providers
        self.dns = dns
        self.smtp = smtp
        self.summary = summary
        self.classification = classification
    }
}
