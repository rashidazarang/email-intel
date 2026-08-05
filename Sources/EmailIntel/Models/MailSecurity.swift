import Foundation

public struct SPFRecord: Codable, Sendable {
    public let raw: String
    public let mechanisms: [String]
    public let policy: String?

    public init(raw: String, mechanisms: [String], policy: String?) {
        self.raw = raw
        self.mechanisms = mechanisms
        self.policy = policy
    }
}

public struct DMARCRecord: Codable, Sendable {
    public let raw: String
    public let policy: String?
    public let subdomainPolicy: String?
    public let rua: [String]
    public let ruf: [String]
    public let pct: Int?

    public init(raw: String, policy: String?, subdomainPolicy: String?, rua: [String], ruf: [String], pct: Int?) {
        self.raw = raw
        self.policy = policy
        self.subdomainPolicy = subdomainPolicy
        self.rua = rua
        self.ruf = ruf
        self.pct = pct
    }
}

public struct DKIMRecord: Codable, Sendable {
    public let selector: String
    public let raw: String

    public init(selector: String, raw: String) {
        self.selector = selector
        self.raw = raw
    }
}

public struct BIMIRecord: Codable, Sendable {
    public let raw: String
    public let location: String?

    public init(raw: String, location: String?) {
        self.raw = raw
        self.location = location
    }
}

public struct MailSecurity: Codable, Sendable {
    public let spf: SPFRecord?
    public let dmarc: DMARCRecord?
    public let dkim: [DKIMRecord]
    public let bimi: BIMIRecord?

    public init(spf: SPFRecord?, dmarc: DMARCRecord?, dkim: [DKIMRecord], bimi: BIMIRecord?) {
        self.spf = spf
        self.dmarc = dmarc
        self.dkim = dkim
        self.bimi = bimi
    }
}

// MARK: - SecurityScore (forward-compatible shell for Step 6)

public enum Severity: String, Codable, Sendable {
    case critical
    case high
    case medium
    case low
    case info
}

public struct Finding: Codable, Sendable {
    public let category: String
    public let severity: Severity
    public let message: String

    public init(category: String, severity: Severity, message: String) {
        self.category = category
        self.severity = severity
        self.message = message
    }
}

public enum SecurityGrade: String, Codable, Sendable {
    case aPlus
    case a
    case b
    case c
    case d
    case f

    public static func from(score: Int) -> SecurityGrade {
        switch score {
        case 95...Int.max: return .aPlus
        case 85...94: return .a
        case 70...84: return .b
        case 55...69: return .c
        case 40...54: return .d
        default: return .f
        }
    }
}

public struct SecurityScore: Codable, Sendable {
    public let score: Int
    public let grade: SecurityGrade
    public let findings: [Finding]

    public init(score: Int, grade: SecurityGrade, findings: [Finding]) {
        self.score = score
        self.grade = grade
        self.findings = findings
    }
}
