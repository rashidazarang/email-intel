import Foundation

/// Top-level orchestrator: walks DNS → parses records → fingerprints → assembles
/// an `EmailIntelligence` dossier for a domain. The actor wraps a `DNSResolver`
/// and the bundled fingerprint database; both are injectable for tests.
public actor EmailIntelligenceEngine {

    private let resolver: DNSResolver
    private let database: EmailFingerprintDatabase

    /// Default DKIM selectors to probe. Covers Google, Microsoft, Mailchimp,
    /// SendGrid, Resend, Mandrill, and the generic `selector1`/`selector2`
    /// rotation used by Microsoft 365.
    public static let defaultDKIMSelectors: [String] = [
        "default", "google", "k1",
        "selector1", "selector2",
        "mandrill", "mailo", "resend",
        "s1", "s2",
        "sig1", "smtp", "dkim",
        "mail",
    ]

    public init(
        resolver: DNSResolver = DNSResolver(),
        database: EmailFingerprintDatabase = .shared
    ) {
        self.resolver = resolver
        self.database = database
    }

    // MARK: - Public orchestrator

    /// Walks DNS for the given domain and assembles an `EmailIntelligence`
    /// dossier. Performs (in order):
    ///   1. MX lookup
    ///   2. Apex TXT lookup (SPF)
    ///   3. `_dmarc.<domain>` TXT lookup
    ///   4. Per-selector `<sel>._domainkey.<domain>` TXT lookup
    ///   5. Parse all records via `MailRecordAnalyzer`
    ///   6. Build a `DNSProfile`
    ///   7. Fingerprint via `EmailFingerprintMatcher`
    ///   8. Score via `SecurityScorer`
    ///   9. Classify via `DomainClassifier`
    ///  10. Assemble final `EmailIntelligence`
    ///
    /// Network failures on any individual lookup are tolerated — the dossier
    /// is built from whatever records resolved successfully.
    public func lookup(
        domain: String,
        dkimSelectors: [String] = defaultDKIMSelectors
    ) async throws -> EmailIntelligence {
        let normalized = domain.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)

        // 1-4. Parallel DNS resolution where possible.
        async let mxTask = (try? resolver.resolveMX(domain: normalized)) ?? []
        async let apexTXTTask = (try? resolver.resolveTXT(domain: normalized)) ?? []
        async let dmarcTXTTask = (try? resolver.resolveTXT(domain: "_dmarc.\(normalized)")) ?? []

        let mxHosts = await mxTask
        let apexTXT = await apexTXTTask
        let dmarcTXT = await dmarcTXTTask

        // DKIM selector probes (sequential to avoid hammering DNS — usually 1-2 hit).
        var foundSelectors: [String] = []
        for sel in dkimSelectors {
            let records = (try? await resolver.resolveTXT(domain: "\(sel)._domainkey.\(normalized)")) ?? []
            if records.contains(where: MailRecordAnalyzer.isDKIMPublicKeyRecord) {
                foundSelectors.append(sel)
            }
        }

        // 5. Parse the records we have.
        let spfRecord = apexTXT.compactMap(MailRecordAnalyzer.parseSPF).first
        let dmarcRecord = dmarcTXT.compactMap(MailRecordAnalyzer.parseDMARC).first

        // 6. Build the DNSProfile.
        let profile = DNSProfile(
            mxRecords: mxHosts,
            spfRecord: spfRecord?.raw,
            dkimFound: !foundSelectors.isEmpty,
            dmarcRecord: dmarcRecord?.raw,
            dmarcPolicy: dmarcRecord?.policy,
            txtRecords: apexTXT
        )

        // 7-10. Hand off to the existing assembler — it handles fingerprinting,
        // scoring, and the summary build.
        return try await assembleFromData(
            domain: normalized,
            dns: profile,
            smtp: nil,
            dkimSelectors: foundSelectors
        )
    }

    // MARK: - Lower-level assembly (used by lookup + tests)

    /// Assemble an `EmailIntelligence` dossier from already-fetched DNS data.
    /// Useful for tests that want to bypass the network and for callers that
    /// already hold a `DNSProfile` (e.g. cached or supplied by another tool).
    public func assembleFromData(
        domain: String,
        dns: DNSProfile,
        smtp: SMTPProfile?,
        dkimSelectors: [String] = []
    ) async throws -> EmailIntelligence {
        let security = SecurityScorer.score(dns: dns, smtp: smtp)

        let fingerprints = try await database.allFingerprints()
        let providers = EmailFingerprintMatcher.match(
            spfRecord: dns.spfRecord,
            mxHosts: dns.mxRecords,
            dkimSelectors: dkimSelectors,
            txtRecords: dns.txtRecords,
            fingerprints: fingerprints
        )

        let mailboxProviders = providers.filter { $0.category == .mailboxProvider }.map(\.name)
        let transactionalServices = providers.filter { $0.category == .transactional }.map(\.name)
        let marketingServices = providers.filter { $0.category == .marketing }.map(\.name)
        let verificationRecords = providers.filter { $0.category == .verification }.map(\.name)
        let totalServices = mailboxProviders.count + transactionalServices.count + marketingServices.count

        let summary = IntelligenceSummary(
            mailboxProviders: mailboxProviders,
            transactionalServices: transactionalServices,
            marketingServices: marketingServices,
            verificationRecords: verificationRecords,
            totalServices: totalServices,
            securityPosture: SecurityScorer.posture(from: security.grade)
        )

        let classification = DomainClassifier.classify(domain: domain, mxHosts: dns.mxRecords)

        return EmailIntelligence(
            domain: domain,
            security: security,
            providers: providers,
            dns: dns,
            smtp: smtp,
            summary: summary,
            classification: classification
        )
    }

    public func analyzeHeaders(rawHeaders: String) -> EmailHeaderAnalysis {
        EmailHeaderParser.parse(rawHeaders: rawHeaders)
    }
}
