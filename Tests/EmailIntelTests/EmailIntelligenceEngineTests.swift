import Testing
import Foundation
@testable import EmailIntel

// MARK: - Full Google Workspace Domain (Grade A+)

@Test func googleWorkspaceDomainGradeAPlus() async throws {
    let engine = EmailIntelligenceEngine()
    let dns = DNSProfile(
        mxRecords: ["aspmx.l.google.com", "alt1.aspmx.l.google.com"],
        spfRecord: "v=spf1 include:_spf.google.com -all",
        dkimFound: true,
        dmarcRecord: "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
        dmarcPolicy: "reject",
        txtRecords: []
    )
    let smtp = SMTPProfile(banner: "220 mx.google.com ESMTP", ehloExtensions: ["STARTTLS"], starttlsSupported: true, tlsVersion: "TLSv1.3")

    let result = try await engine.assembleFromData(domain: "example.com", dns: dns, smtp: smtp, dkimSelectors: ["google"])

    #expect(result.domain == "example.com")
    #expect(result.security.grade == .aPlus)
    #expect(result.security.score == 100)

    let google = result.providers.first { $0.id == "google-workspace" }
    #expect(google != nil)
    #expect(google?.category == .mailboxProvider)
}

// MARK: - Bare Domain (Grade F)

@Test func bareDomainGradeF() async throws {
    let engine = EmailIntelligenceEngine()
    let dns = DNSProfile(
        mxRecords: [],
        spfRecord: nil,
        dkimFound: false,
        dmarcRecord: nil,
        dmarcPolicy: nil,
        txtRecords: []
    )
    let smtp = SMTPProfile(banner: nil, ehloExtensions: [], starttlsSupported: false, tlsVersion: nil)

    let result = try await engine.assembleFromData(domain: "bare.example.com", dns: dns, smtp: smtp)

    #expect(result.security.grade == .f)
    #expect(result.security.score == 0)
    #expect(result.providers.isEmpty)
    #expect(result.security.findings.count >= 4) // SPF, DKIM, DMARC, TLS
}

// MARK: - Partial Security (Grade C-D Range)

@Test func partialSecurityGradeCDRange() async throws {
    let engine = EmailIntelligenceEngine()
    let dns = DNSProfile(
        mxRecords: ["mail.example.com"],
        spfRecord: "v=spf1 include:example.com ~all",
        dkimFound: false,
        dmarcRecord: "v=DMARC1; p=none",
        dmarcPolicy: "none",
        txtRecords: []
    )

    let result = try await engine.assembleFromData(domain: "partial.example.com", dns: dns, smtp: nil)

    // SPF ~all=20, DKIM=0, DMARC none=10, TLS not probed=15 → total=45
    #expect(result.security.score >= 40)
    #expect(result.security.score < 70)
    #expect(result.security.grade == .d || result.security.grade == .c)
}

// MARK: - Provider Categorization

@Test func providerCategorization() async throws {
    let engine = EmailIntelligenceEngine()
    let dns = DNSProfile(
        mxRecords: ["aspmx.l.google.com"],
        spfRecord: "v=spf1 include:_spf.google.com include:sendgrid.net -all",
        dkimFound: true,
        dmarcRecord: "v=DMARC1; p=reject",
        dmarcPolicy: "reject",
        txtRecords: []
    )
    let smtp = SMTPProfile(banner: nil, ehloExtensions: [], starttlsSupported: true, tlsVersion: nil)

    let result = try await engine.assembleFromData(domain: "biz.example.com", dns: dns, smtp: smtp, dkimSelectors: ["google", "s1"])

    let google = result.providers.first { $0.id == "google-workspace" }
    let sendgrid = result.providers.first { $0.id == "sendgrid" }

    #expect(google?.category == .mailboxProvider)
    #expect(sendgrid?.category == .transactional)
}

@Test func resendProviderCategorization() async throws {
    let engine = EmailIntelligenceEngine()
    let dns = DNSProfile(
        mxRecords: [],
        spfRecord: "v=spf1 include:spf.resend.com -all",
        dkimFound: true,
        dmarcRecord: "v=DMARC1; p=none",
        dmarcPolicy: "none",
        txtRecords: []
    )

    let result = try await engine.assembleFromData(
        domain: "warmup.example.com",
        dns: dns,
        smtp: nil,
        dkimSelectors: ["resend"]
    )

    let resend = result.providers.first { $0.id == "resend" }
    #expect(resend?.category == .transactional)
    #expect(result.summary.transactionalServices.contains("Resend"))
}

// MARK: - Summary Generation

@Test func summaryCorrectCounts() async throws {
    let engine = EmailIntelligenceEngine()
    let dns = DNSProfile(
        mxRecords: ["aspmx.l.google.com"],
        spfRecord: "v=spf1 include:_spf.google.com include:sendgrid.net include:servers.mcsv.net -all",
        dkimFound: true,
        dmarcRecord: "v=DMARC1; p=reject",
        dmarcPolicy: "reject",
        txtRecords: ["google-site-verification=abc123"]
    )
    let smtp = SMTPProfile(banner: nil, ehloExtensions: [], starttlsSupported: true, tlsVersion: nil)

    let result = try await engine.assembleFromData(domain: "full.example.com", dns: dns, smtp: smtp, dkimSelectors: ["google", "s1", "k1"])

    #expect(result.summary.mailboxProviders.contains("Google Workspace"))
    #expect(result.summary.transactionalServices.contains("SendGrid"))
    #expect(result.summary.marketingServices.contains("Mailchimp"))
    #expect(result.summary.verificationRecords.contains("Google Site Verification"))
    // totalServices should not count verification records
    #expect(result.summary.totalServices >= 3)
}

@Test func summarySecurityPosture() async throws {
    let engine = EmailIntelligenceEngine()

    // Strict posture (A/A+)
    let strictDNS = DNSProfile(mxRecords: [], spfRecord: "v=spf1 -all", dkimFound: true, dmarcRecord: nil, dmarcPolicy: "reject", txtRecords: [])
    let strictSMTP = SMTPProfile(banner: nil, ehloExtensions: [], starttlsSupported: true, tlsVersion: nil)
    let strict = try await engine.assembleFromData(domain: "strict.example.com", dns: strictDNS, smtp: strictSMTP)
    #expect(strict.summary.securityPosture == "strict")

    // Minimal posture (F)
    let minimalDNS = DNSProfile(mxRecords: [], spfRecord: nil, dkimFound: false, dmarcRecord: nil, dmarcPolicy: nil, txtRecords: [])
    let minimalSMTP = SMTPProfile(banner: nil, ehloExtensions: [], starttlsSupported: false, tlsVersion: nil)
    let minimal = try await engine.assembleFromData(domain: "minimal.example.com", dns: minimalDNS, smtp: minimalSMTP)
    #expect(minimal.summary.securityPosture == "minimal")
}

// MARK: - JSON Round-Trip

@Test func jsonRoundTrip() async throws {
    let engine = EmailIntelligenceEngine()
    let dns = DNSProfile(
        mxRecords: ["aspmx.l.google.com"],
        spfRecord: "v=spf1 include:_spf.google.com -all",
        dkimFound: true,
        dmarcRecord: "v=DMARC1; p=reject",
        dmarcPolicy: "reject",
        txtRecords: ["google-site-verification=test"]
    )
    let smtp = SMTPProfile(banner: "220 mx.google.com ESMTP", ehloExtensions: ["STARTTLS"], starttlsSupported: true, tlsVersion: "TLSv1.3")

    let original = try await engine.assembleFromData(domain: "roundtrip.example.com", dns: dns, smtp: smtp, dkimSelectors: ["google"])

    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    let data = try encoder.encode(original)

    let decoder = JSONDecoder()
    let decoded = try decoder.decode(EmailIntelligence.self, from: data)

    #expect(decoded.domain == original.domain)
    #expect(decoded.security.score == original.security.score)
    #expect(decoded.security.grade == original.security.grade)
    #expect(decoded.providers.count == original.providers.count)
    #expect(decoded.dns.spfRecord == original.dns.spfRecord)
    #expect(decoded.smtp?.banner == original.smtp?.banner)
    #expect(decoded.summary.totalServices == original.summary.totalServices)
    #expect(decoded.summary.securityPosture == original.summary.securityPosture)
}

// MARK: - No SMTP Profile

@Test func noSMTPStillProducesResult() async throws {
    let engine = EmailIntelligenceEngine()
    let dns = DNSProfile(
        mxRecords: ["mail.example.com"],
        spfRecord: "v=spf1 -all",
        dkimFound: true,
        dmarcRecord: "v=DMARC1; p=reject",
        dmarcPolicy: "reject",
        txtRecords: []
    )

    let result = try await engine.assembleFromData(domain: "nosmtp.example.com", dns: dns, smtp: nil)

    #expect(result.smtp == nil)
    // Should still have a valid score with TLS partial credit
    #expect(result.security.score > 0)
}

// MARK: - Header Analysis (Synchronous)

@Test func headerAnalysisIsSynchronous() async {
    let engine = EmailIntelligenceEngine()
    let raw = """
    Received: from mail.example.com by mx.example.com with ESMTPS; Fri, 10 Apr 2026 14:30:00 +0000
    Authentication-Results: mx.example.com; spf=pass; dkim=pass
    """
    let analysis = await engine.analyzeHeaders(rawHeaders: raw)
    #expect(analysis.receivedChain.count == 1)
    #expect(analysis.authenticationResults.count == 1)
}

// MARK: - Empty Provider List

@Test func noDNSSignalsProducesEmptyProviders() async throws {
    let engine = EmailIntelligenceEngine()
    let dns = DNSProfile(
        mxRecords: ["mail.custom.example.com"],
        spfRecord: "v=spf1 ip4:10.0.0.1 -all",
        dkimFound: false,
        dmarcRecord: nil,
        dmarcPolicy: nil,
        txtRecords: []
    )

    let result = try await engine.assembleFromData(domain: "custom.example.com", dns: dns, smtp: nil)
    #expect(result.providers.isEmpty)
    #expect(result.summary.totalServices == 0)
}
