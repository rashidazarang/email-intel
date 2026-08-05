import Foundation

struct SecurityScorer: Sendable {

    static func score(dns: DNSProfile, smtp: SMTPProfile?) -> SecurityScore {
        var totalScore = 0
        var findings: [Finding] = []

        // SPF dimension (max 25)
        if let spf = dns.spfRecord {
            if spf.contains("-all") {
                totalScore += 25
            } else if spf.contains("~all") {
                totalScore += 20
            } else if spf.contains("?all") {
                totalScore += 10
            } else if spf.contains("+all") {
                totalScore += 5
                findings.append(Finding(
                    category: "SPF",
                    severity: .critical,
                    message: "SPF record uses permissive +all policy, allowing any server to send email"
                ))
            }
        } else {
            findings.append(Finding(
                category: "SPF",
                severity: .high,
                message: "No SPF record found"
            ))
        }

        // DKIM dimension (max 25)
        if dns.dkimFound {
            totalScore += 25
        } else {
            findings.append(Finding(
                category: "DKIM",
                severity: .high,
                message: "No DKIM record found"
            ))
        }

        // DMARC dimension (max 25)
        if let policy = dns.dmarcPolicy {
            switch policy {
            case "reject":
                totalScore += 25
            case "quarantine":
                totalScore += 20
            case "none":
                totalScore += 10
                findings.append(Finding(
                    category: "DMARC",
                    severity: .medium,
                    message: "DMARC policy set to none — no enforcement"
                ))
            default:
                findings.append(Finding(
                    category: "DMARC",
                    severity: .high,
                    message: "Unrecognized DMARC policy"
                ))
            }
        } else {
            findings.append(Finding(
                category: "DMARC",
                severity: .high,
                message: "No DMARC record found"
            ))
        }

        // TLS dimension (max 25)
        if let smtp = smtp {
            if smtp.starttlsSupported {
                totalScore += 25
            } else {
                findings.append(Finding(
                    category: "TLS",
                    severity: .high,
                    message: "STARTTLS not supported"
                ))
            }
        } else {
            totalScore += 15
            findings.append(Finding(
                category: "TLS",
                severity: .info,
                message: "SMTP not probed — TLS status unknown"
            ))
        }

        let grade = SecurityGrade.from(score: totalScore)
        return SecurityScore(score: totalScore, grade: grade, findings: findings)
    }

    static func posture(from grade: SecurityGrade) -> String {
        switch grade {
        case .aPlus, .a:
            return "strict"
        case .b:
            return "moderate"
        case .c, .d, .f:
            return "minimal"
        }
    }
}
