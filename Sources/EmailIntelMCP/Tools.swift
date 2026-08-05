import EmailIntel
import Foundation
import os

enum Tools {

    private static let logger = Logger(subsystem: "com.rashidazarang.emailintel", category: "Tools")

    // MARK: - email_intel

    static func emailIntel(_ args: [String: Any]) async throws -> Any {
        guard let domain = args["domain"] as? String else {
            throw ToolError.invalidParams("missing required parameter 'domain'")
        }

        let resolver = DNSResolver()
        let inspection = try await buildDNSProfile(domain: domain, resolver: resolver)
        let dns = inspection.profile
        let security = scoreSecurity(dns: dns, smtp: nil)

        let fingerprints = try await EmailFingerprintDatabase.shared.allFingerprints()
        let providers = EmailFingerprintMatcher.match(
            spfRecord: dns.spfRecord,
            mxHosts: dns.mxRecords,
            dkimSelectors: inspection.dkimSelectors,
            txtRecords: dns.txtRecords,
            fingerprints: fingerprints
        )

        let mailbox = providers.filter { $0.category == .mailboxProvider }.map(\.name)
        let transactional = providers.filter { $0.category == .transactional }.map(\.name)
        let marketing = providers.filter { $0.category == .marketing }.map(\.name)
        let verification = providers.filter { $0.category == .verification }.map(\.name)

        let summary = IntelligenceSummary(
            mailboxProviders: mailbox,
            transactionalServices: transactional,
            marketingServices: marketing,
            verificationRecords: verification,
            totalServices: mailbox.count + transactional.count + marketing.count,
            securityPosture: posture(from: security.grade)
        )

        let intel = EmailIntelligence(
            domain: domain,
            security: security,
            providers: providers,
            dns: dns,
            smtp: nil,
            summary: summary
        )

        return try encodableToJSON(intel)
    }

    // MARK: - dns_lookup

    static func dnsLookup(_ args: [String: Any]) async throws -> Any {
        guard let domain = args["domain"] as? String else {
            throw ToolError.invalidParams("missing required parameter 'domain'")
        }

        let resolver = DNSResolver()
        let inspection = try await buildDNSProfile(domain: domain, resolver: resolver)
        return try encodableToJSON(inspection.profile)
    }

    // MARK: - smtp_probe

    static func smtpProbe(_ args: [String: Any]) async throws -> Any {
        guard let host = args["host"] as? String else {
            throw ToolError.invalidParams("missing required parameter 'host'")
        }
        let port = (args["port"] as? Int) ?? 25
        guard port > 0, port <= 65535 else {
            throw ToolError.invalidParams("port must be 1-65535")
        }

        let profile = await performSMTPProbe(host: host, port: UInt16(port))
        return try encodableToJSON(profile)
    }

    // MARK: - email_headers

    static func emailHeaders(_ args: [String: Any]) async throws -> Any {
        guard let rawHeaders = args["raw_headers"] as? String else {
            throw ToolError.invalidParams("missing required parameter 'raw_headers'")
        }

        let analysis = EmailHeaderParser.parse(rawHeaders: rawHeaders)
        return try encodableToJSON(analysis)
    }

    // MARK: - DNS Profile Builder

    private struct DNSInspection: Sendable {
        let profile: DNSProfile
        let dkimSelectors: [String]
    }

    private static func buildDNSProfile(
        domain: String,
        resolver: DNSResolver
    ) async throws -> DNSInspection {
        async let mxTask = resolver.resolveMX(domain: domain)
        async let txtTask = resolver.resolveTXT(domain: domain)
        async let dmarcTask = resolver.resolveTXT(domain: "_dmarc.\(domain)")

        let mx = (try? await mxTask) ?? []
        let txt = (try? await txtTask) ?? []
        let dmarcRecords = (try? await dmarcTask) ?? []

        let spf = txt.first { $0.lowercased().hasPrefix("v=spf1") }
        let dmarc = dmarcRecords.first { $0.lowercased().hasPrefix("v=dmarc1") }
        let dmarcPolicy = dmarc.flatMap { MailRecordAnalyzer.parseDMARC($0) }?.policy

        // Probe the same selector set used by the CLI engine.
        var foundSelectors: [String] = []
        for selector in EmailIntelligenceEngine.defaultDKIMSelectors {
            if let records = try? await resolver.resolveTXT(
                domain: "\(selector)._domainkey.\(domain)"
            ), records.contains(where: MailRecordAnalyzer.isDKIMPublicKeyRecord) {
                foundSelectors.append(selector)
            }
        }

        let profile = DNSProfile(
            mxRecords: mx,
            spfRecord: spf,
            dkimFound: !foundSelectors.isEmpty,
            dmarcRecord: dmarc,
            dmarcPolicy: dmarcPolicy,
            txtRecords: txt
        )
        return DNSInspection(profile: profile, dkimSelectors: foundSelectors)
    }

    // MARK: - Security Scoring (mirrors internal SecurityScorer)

    private static func scoreSecurity(dns: DNSProfile, smtp: SMTPProfile?) -> SecurityScore {
        var total = 0
        var findings: [Finding] = []

        // SPF (max 25)
        if let spf = dns.spfRecord {
            if spf.contains("-all") {
                total += 25
            } else if spf.contains("~all") {
                total += 20
            } else if spf.contains("?all") {
                total += 10
            } else if spf.contains("+all") {
                total += 5
                findings.append(Finding(
                    category: "SPF", severity: .critical,
                    message: "SPF record uses permissive +all policy, allowing any server to send email"
                ))
            }
        } else {
            findings.append(Finding(category: "SPF", severity: .high, message: "No SPF record found"))
        }

        // DKIM (max 25)
        if dns.dkimFound {
            total += 25
        } else {
            findings.append(Finding(category: "DKIM", severity: .high, message: "No DKIM record found"))
        }

        // DMARC (max 25)
        if let policy = dns.dmarcPolicy {
            switch policy {
            case "reject": total += 25
            case "quarantine": total += 20
            case "none":
                total += 10
                findings.append(Finding(
                    category: "DMARC", severity: .medium,
                    message: "DMARC policy set to none — no enforcement"
                ))
            default:
                findings.append(Finding(
                    category: "DMARC", severity: .high,
                    message: "Unrecognized DMARC policy"
                ))
            }
        } else {
            findings.append(Finding(category: "DMARC", severity: .high, message: "No DMARC record found"))
        }

        // TLS (max 25)
        if let smtp {
            if smtp.starttlsSupported {
                total += 25
            } else {
                findings.append(Finding(
                    category: "TLS", severity: .high, message: "STARTTLS not supported"
                ))
            }
        } else {
            total += 15
            findings.append(Finding(
                category: "TLS", severity: .info,
                message: "SMTP not probed — TLS status unknown"
            ))
        }

        let grade = SecurityGrade.from(score: total)
        return SecurityScore(score: total, grade: grade, findings: findings)
    }

    private static func posture(from grade: SecurityGrade) -> String {
        switch grade {
        case .aPlus, .a: return "strict"
        case .b: return "moderate"
        case .c, .d, .f: return "minimal"
        }
    }

    // MARK: - JSON Helpers

    private static func encodableToJSON<T: Encodable>(_ value: T) throws -> Any {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(value)
        return try JSONSerialization.jsonObject(with: data)
    }

    // MARK: - SMTP Probing (POSIX sockets)

    private static func performSMTPProbe(host: String, port: UInt16) async -> SMTPProfile {
        let empty = SMTPProfile(
            banner: nil, ehloExtensions: [],
            starttlsSupported: false, tlsVersion: nil
        )
        return await withCheckedContinuation { continuation in
            DispatchQueue.global().async {
                let profile = blockingSMTPProbe(host: host, port: port) ?? empty
                continuation.resume(returning: profile)
            }
        }
    }

    private static func blockingSMTPProbe(host: String, port: UInt16) -> SMTPProfile? {
        // Resolve hostname
        var hints = addrinfo()
        hints.ai_family = AF_INET
        hints.ai_socktype = SOCK_STREAM
        hints.ai_protocol = IPPROTO_TCP

        var addrResult: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &addrResult) == 0,
              let addrInfo = addrResult else { return nil }
        defer { freeaddrinfo(addrResult) }

        // Create socket
        let sock = socket(addrInfo.pointee.ai_family,
                          addrInfo.pointee.ai_socktype,
                          addrInfo.pointee.ai_protocol)
        guard sock >= 0 else { return nil }
        defer { Darwin.close(sock) }

        // Set 15-second timeouts
        var timeout = timeval(tv_sec: 15, tv_usec: 0)
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   socklen_t(MemoryLayout<timeval>.size))
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                   socklen_t(MemoryLayout<timeval>.size))

        // Connect
        guard Darwin.connect(sock, addrInfo.pointee.ai_addr,
                             addrInfo.pointee.ai_addrlen) == 0 else { return nil }

        // Read 220 banner
        guard let bannerResponse = recvString(sock) else { return nil }

        let banner: String?
        if bannerResponse.hasPrefix("220") {
            let line = bannerResponse.components(separatedBy: "\r\n").first ?? bannerResponse
            let parts = line.split(separator: " ", maxSplits: 1)
            banner = parts.count > 1 ? String(parts[1]) : nil
        } else {
            return nil
        }

        // Send EHLO
        guard sendString(sock, "EHLO email-intel\r\n") else {
            return SMTPProfile(banner: banner, ehloExtensions: [],
                               starttlsSupported: false, tlsVersion: nil)
        }

        // Read EHLO multi-line response
        guard let ehloResponse = recvMultiLine(sock) else {
            return SMTPProfile(banner: banner, ehloExtensions: [],
                               starttlsSupported: false, tlsVersion: nil)
        }

        var extensions: [String] = []
        for line in ehloResponse.components(separatedBy: "\r\n") {
            if line.hasPrefix("250-") || line.hasPrefix("250 ") {
                let ext = String(line.dropFirst(4)).trimmingCharacters(in: .whitespaces)
                if !ext.isEmpty { extensions.append(ext) }
            }
        }

        let starttls = extensions.contains { $0.uppercased() == "STARTTLS" }

        // Send QUIT
        _ = sendString(sock, "QUIT\r\n")

        return SMTPProfile(banner: banner, ehloExtensions: extensions,
                           starttlsSupported: starttls, tlsVersion: nil)
    }

    private static func recvString(_ sock: Int32) -> String? {
        var buffer = [UInt8](repeating: 0, count: 4096)
        let n = recv(sock, &buffer, buffer.count, 0)
        guard n > 0 else { return nil }
        return String(bytes: buffer[0..<n], encoding: .utf8)
    }

    private static func recvMultiLine(_ sock: Int32) -> String? {
        var accumulated = Data()
        while accumulated.count < 65536 {
            var buffer = [UInt8](repeating: 0, count: 4096)
            let n = recv(sock, &buffer, buffer.count, 0)
            guard n > 0 else { break }
            accumulated.append(contentsOf: buffer[0..<n])
            // Check for a final response line: 3 digits followed by a space
            if let str = String(data: accumulated, encoding: .utf8) {
                for line in str.components(separatedBy: "\r\n") where line.count >= 4 {
                    let idx = line.index(line.startIndex, offsetBy: 3)
                    if line.prefix(3).allSatisfy(\.isNumber) && line[idx] == " " {
                        return str
                    }
                }
            }
        }
        return accumulated.isEmpty ? nil : String(data: accumulated, encoding: .utf8)
    }

    private static func sendString(_ sock: Int32, _ string: String) -> Bool {
        guard let data = string.data(using: .utf8) else { return false }
        return data.withUnsafeBytes { ptr -> Bool in
            guard let base = ptr.baseAddress else { return false }
            return Darwin.send(sock, base, ptr.count, 0) > 0
        }
    }
}

// MARK: - ToolError

enum ToolError: Error, Sendable {
    case invalidParams(String)
}
