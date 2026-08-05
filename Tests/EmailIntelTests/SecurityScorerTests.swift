import Testing
import Foundation
@testable import EmailIntel

// MARK: - Perfect Score

@Test func perfectSecurityScore() {
    let dns = DNSProfile(
        mxRecords: ["mail.example.com"],
        spfRecord: "v=spf1 include:_spf.google.com -all",
        dkimFound: true,
        dmarcRecord: "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
        dmarcPolicy: "reject",
        txtRecords: []
    )
    let smtp = SMTPProfile(banner: "220 mail.example.com ESMTP", ehloExtensions: ["STARTTLS"], starttlsSupported: true, tlsVersion: "TLSv1.3")
    let result = SecurityScorer.score(dns: dns, smtp: smtp)

    #expect(result.score == 100)
    #expect(result.grade == .aPlus)
}

// MARK: - Individual Dimensions

@Test func spfHardfailFull25Points() {
    let dns = DNSProfile(mxRecords: [], spfRecord: "v=spf1 include:example.com -all", dkimFound: false, dmarcRecord: nil, dmarcPolicy: nil, txtRecords: [])
    let result = SecurityScorer.score(dns: dns, smtp: nil)
    // SPF=25, DKIM=0, DMARC=0, TLS=15 (not probed)
    #expect(result.score == 40)
}

@Test func spfSoftfail20Points() {
    let dns = DNSProfile(mxRecords: [], spfRecord: "v=spf1 include:example.com ~all", dkimFound: false, dmarcRecord: nil, dmarcPolicy: nil, txtRecords: [])
    let result = SecurityScorer.score(dns: dns, smtp: nil)
    // SPF=20, DKIM=0, DMARC=0, TLS=15
    #expect(result.score == 35)
}

@Test func spfNeutral10Points() {
    let dns = DNSProfile(mxRecords: [], spfRecord: "v=spf1 include:example.com ?all", dkimFound: false, dmarcRecord: nil, dmarcPolicy: nil, txtRecords: [])
    let result = SecurityScorer.score(dns: dns, smtp: nil)
    // SPF=10, DKIM=0, DMARC=0, TLS=15
    #expect(result.score == 25)
}

@Test func spfPlusAllCritical5Points() {
    let dns = DNSProfile(mxRecords: [], spfRecord: "v=spf1 +all", dkimFound: false, dmarcRecord: nil, dmarcPolicy: nil, txtRecords: [])
    let result = SecurityScorer.score(dns: dns, smtp: nil)
    // SPF=5, DKIM=0, DMARC=0, TLS=15
    #expect(result.score == 20)
    let spfFinding = result.findings.first { $0.category == "SPF" }
    #expect(spfFinding?.severity == .critical)
}

@Test func noSPF0Points() {
    let dns = DNSProfile(mxRecords: [], spfRecord: nil, dkimFound: false, dmarcRecord: nil, dmarcPolicy: nil, txtRecords: [])
    let result = SecurityScorer.score(dns: dns, smtp: nil)
    // SPF=0, DKIM=0, DMARC=0, TLS=15
    #expect(result.score == 15)
    let spfFinding = result.findings.first { $0.category == "SPF" }
    #expect(spfFinding?.severity == .high)
}

@Test func dkimPresent25Points() {
    let dns = DNSProfile(mxRecords: [], spfRecord: nil, dkimFound: true, dmarcRecord: nil, dmarcPolicy: nil, txtRecords: [])
    let result = SecurityScorer.score(dns: dns, smtp: nil)
    // SPF=0, DKIM=25, DMARC=0, TLS=15
    #expect(result.score == 40)
}

@Test func dkimAbsent0Points() {
    let dns = DNSProfile(mxRecords: [], spfRecord: nil, dkimFound: false, dmarcRecord: nil, dmarcPolicy: nil, txtRecords: [])
    let result = SecurityScorer.score(dns: dns, smtp: nil)
    let dkimFinding = result.findings.first { $0.category == "DKIM" }
    #expect(dkimFinding != nil)
    #expect(dkimFinding?.severity == .high)
}

@Test func dmarcReject25Points() {
    let dns = DNSProfile(mxRecords: [], spfRecord: nil, dkimFound: false, dmarcRecord: nil, dmarcPolicy: "reject", txtRecords: [])
    let result = SecurityScorer.score(dns: dns, smtp: nil)
    // SPF=0, DKIM=0, DMARC=25, TLS=15
    #expect(result.score == 40)
}

@Test func dmarcQuarantine20Points() {
    let dns = DNSProfile(mxRecords: [], spfRecord: nil, dkimFound: false, dmarcRecord: nil, dmarcPolicy: "quarantine", txtRecords: [])
    let result = SecurityScorer.score(dns: dns, smtp: nil)
    // SPF=0, DKIM=0, DMARC=20, TLS=15
    #expect(result.score == 35)
}

@Test func dmarcNone10Points() {
    let dns = DNSProfile(mxRecords: [], spfRecord: nil, dkimFound: false, dmarcRecord: nil, dmarcPolicy: "none", txtRecords: [])
    let result = SecurityScorer.score(dns: dns, smtp: nil)
    // SPF=0, DKIM=0, DMARC=10, TLS=15
    #expect(result.score == 25)
    let dmarcFinding = result.findings.first { $0.category == "DMARC" }
    #expect(dmarcFinding?.severity == .medium)
}

@Test func noDMARC0Points() {
    let dns = DNSProfile(mxRecords: [], spfRecord: nil, dkimFound: false, dmarcRecord: nil, dmarcPolicy: nil, txtRecords: [])
    let result = SecurityScorer.score(dns: dns, smtp: nil)
    let dmarcFinding = result.findings.first { $0.category == "DMARC" }
    #expect(dmarcFinding != nil)
    #expect(dmarcFinding?.severity == .high)
}

@Test func tlsSupported25Points() {
    let dns = DNSProfile(mxRecords: [], spfRecord: nil, dkimFound: false, dmarcRecord: nil, dmarcPolicy: nil, txtRecords: [])
    let smtp = SMTPProfile(banner: nil, ehloExtensions: [], starttlsSupported: true, tlsVersion: nil)
    let result = SecurityScorer.score(dns: dns, smtp: smtp)
    // SPF=0, DKIM=0, DMARC=0, TLS=25
    #expect(result.score == 25)
}

@Test func tlsNotSupported0Points() {
    let dns = DNSProfile(mxRecords: [], spfRecord: nil, dkimFound: false, dmarcRecord: nil, dmarcPolicy: nil, txtRecords: [])
    let smtp = SMTPProfile(banner: nil, ehloExtensions: [], starttlsSupported: false, tlsVersion: nil)
    let result = SecurityScorer.score(dns: dns, smtp: smtp)
    // SPF=0, DKIM=0, DMARC=0, TLS=0
    #expect(result.score == 0)
    let tlsFinding = result.findings.first { $0.category == "TLS" }
    #expect(tlsFinding?.severity == .high)
}

@Test func noSMTPProbe15PointsPartialCredit() {
    let dns = DNSProfile(mxRecords: [], spfRecord: nil, dkimFound: false, dmarcRecord: nil, dmarcPolicy: nil, txtRecords: [])
    let result = SecurityScorer.score(dns: dns, smtp: nil)
    // TLS gets 15 partial credit when not probed
    let tlsFinding = result.findings.first { $0.category == "TLS" }
    #expect(tlsFinding?.severity == .info)
}

// MARK: - Grade Boundaries

@Test func gradeBoundaryAPlus95() {
    #expect(SecurityGrade.from(score: 95) == .aPlus)
    #expect(SecurityGrade.from(score: 100) == .aPlus)
}

@Test func gradeBoundaryA85to94() {
    #expect(SecurityGrade.from(score: 85) == .a)
    #expect(SecurityGrade.from(score: 94) == .a)
}

@Test func gradeBoundaryB70to84() {
    #expect(SecurityGrade.from(score: 70) == .b)
    #expect(SecurityGrade.from(score: 84) == .b)
}

@Test func gradeBoundaryC55to69() {
    #expect(SecurityGrade.from(score: 55) == .c)
    #expect(SecurityGrade.from(score: 69) == .c)
}

@Test func gradeBoundaryD40to54() {
    #expect(SecurityGrade.from(score: 40) == .d)
    #expect(SecurityGrade.from(score: 54) == .d)
}

@Test func gradeBoundaryFBelow40() {
    #expect(SecurityGrade.from(score: 39) == .f)
    #expect(SecurityGrade.from(score: 0) == .f)
}

// MARK: - Findings Generation

@Test func missingSPFGeneratesFinding() {
    let dns = DNSProfile(mxRecords: [], spfRecord: nil, dkimFound: true, dmarcRecord: nil, dmarcPolicy: "reject", txtRecords: [])
    let smtp = SMTPProfile(banner: nil, ehloExtensions: [], starttlsSupported: true, tlsVersion: nil)
    let result = SecurityScorer.score(dns: dns, smtp: smtp)
    #expect(result.findings.contains { $0.category == "SPF" })
}

@Test func spfPlusAllGeneratesCriticalFinding() {
    let dns = DNSProfile(mxRecords: [], spfRecord: "v=spf1 +all", dkimFound: true, dmarcRecord: nil, dmarcPolicy: "reject", txtRecords: [])
    let smtp = SMTPProfile(banner: nil, ehloExtensions: [], starttlsSupported: true, tlsVersion: nil)
    let result = SecurityScorer.score(dns: dns, smtp: smtp)
    let spfFinding = result.findings.first { $0.category == "SPF" }
    #expect(spfFinding?.severity == .critical)
}

@Test func dmarcNoneGeneratesFinding() {
    let dns = DNSProfile(mxRecords: [], spfRecord: "v=spf1 -all", dkimFound: true, dmarcRecord: nil, dmarcPolicy: "none", txtRecords: [])
    let smtp = SMTPProfile(banner: nil, ehloExtensions: [], starttlsSupported: true, tlsVersion: nil)
    let result = SecurityScorer.score(dns: dns, smtp: smtp)
    #expect(result.findings.contains { $0.category == "DMARC" })
}

// MARK: - Posture Mapping

@Test func postureStrict() {
    #expect(SecurityScorer.posture(from: .aPlus) == "strict")
    #expect(SecurityScorer.posture(from: .a) == "strict")
}

@Test func postureModerate() {
    #expect(SecurityScorer.posture(from: .b) == "moderate")
}

@Test func postureMinimal() {
    #expect(SecurityScorer.posture(from: .c) == "minimal")
    #expect(SecurityScorer.posture(from: .d) == "minimal")
    #expect(SecurityScorer.posture(from: .f) == "minimal")
}
