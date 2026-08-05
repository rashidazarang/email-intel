import Testing
import Foundation
@testable import EmailIntel

// MARK: - DomainClassifier

@Test func classifierDetectsWebmail() {
    let result = DomainClassifier.classify(domain: "gmail.com", mxHosts: [])
    #expect(result.isWebmail == true)
    #expect(result.isDisposable == false)
}

@Test func classifierDetectsWebmailCaseInsensitive() {
    let result = DomainClassifier.classify(domain: "GMAIL.COM", mxHosts: [])
    #expect(result.isWebmail == true)
}

@Test func classifierDetectsDisposable() {
    let result = DomainClassifier.classify(domain: "mailinator.com", mxHosts: [])
    #expect(result.isDisposable == true)
    #expect(result.isWebmail == false)
}

@Test func classifierDerivesGoogleWorkspaceFromMX() {
    let result = DomainClassifier.classify(
        domain: "example.com",
        mxHosts: ["aspmx.l.google.com", "alt1.aspmx.l.google.com"]
    )
    #expect(result.mxProvider == "Google Workspace")
    #expect(result.isWebmail == false) // example.com is not webmail itself
}

@Test func classifierDerivesMicrosoft365FromMX() {
    let result = DomainClassifier.classify(
        domain: "example.com",
        mxHosts: ["example-com.mail.protection.outlook.com"]
    )
    #expect(result.mxProvider == "Microsoft 365")
}

@Test func classifierDerivesProofpointFromMX() {
    let result = DomainClassifier.classify(
        domain: "example.com",
        mxHosts: ["mx0a-12345.pphosted.com"]
    )
    #expect(result.mxProvider == "Proofpoint")
}

@Test func classifierReturnsNilProviderWhenNoMatch() {
    let result = DomainClassifier.classify(
        domain: "example.com",
        mxHosts: ["mail.unknown-host.example"]
    )
    #expect(result.mxProvider == nil)
}

@Test func classifierEmptyMXReturnsNilProvider() {
    let result = DomainClassifier.classify(domain: "example.com", mxHosts: [])
    #expect(result.mxProvider == nil)
}

// MARK: - EmailIntelligenceEngine.assembleFromData (offline path)

@Test func engineAssemblesFromCachedData() async throws {
    let dns = DNSProfile(
        mxRecords: ["aspmx.l.google.com"],
        spfRecord: "v=spf1 include:_spf.google.com ~all",
        dkimFound: true,
        dmarcRecord: "v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
        dmarcPolicy: "reject",
        txtRecords: ["v=spf1 include:_spf.google.com ~all", "google-site-verification=abc"]
    )

    let engine = EmailIntelligenceEngine()
    let intel = try await engine.assembleFromData(
        domain: "example.com",
        dns: dns,
        smtp: nil,
        dkimSelectors: ["google"]
    )

    #expect(intel.domain == "example.com")
    #expect(intel.classification != nil)
    #expect(intel.classification?.mxProvider == "Google Workspace")
    #expect(intel.dns.dkimFound == true)
}

@Test func engineDefaultDKIMSelectorsExposed() {
    // Sanity: the public selector list is non-empty and includes the
    // generic Microsoft selectors that callers usually want.
    #expect(EmailIntelligenceEngine.defaultDKIMSelectors.contains("selector1"))
    #expect(EmailIntelligenceEngine.defaultDKIMSelectors.contains("google"))
    #expect(EmailIntelligenceEngine.defaultDKIMSelectors.contains("resend"))
    #expect(EmailIntelligenceEngine.defaultDKIMSelectors.count >= 8)
}

@Test func dkimPublicKeyRecordAcceptsProviderPOnlyRecords() {
    let resendRecord = "p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"
    let parsed = MailRecordAnalyzer.parseDKIM(selector: "resend", raw: resendRecord)

    #expect(MailRecordAnalyzer.isDKIMPublicKeyRecord(resendRecord))
    #expect(parsed?.selector == "resend")
    #expect(parsed?.raw == resendRecord)
}

@Test func dkimPublicKeyRecordRejectsEmptyPRecords() {
    #expect(MailRecordAnalyzer.isDKIMPublicKeyRecord("p=") == false)
    #expect(MailRecordAnalyzer.isDKIMPublicKeyRecord("v=DKIM1; p=") == false)
    #expect(MailRecordAnalyzer.parseDKIM(selector: "resend", raw: "p=") == nil)
}

// MARK: - EmailIntelligence Codable round-trip

@Test func emailIntelligenceCodableRoundTrip() async throws {
    let dns = DNSProfile(
        mxRecords: ["mx.example.com"],
        spfRecord: "v=spf1 -all",
        dkimFound: false,
        dmarcRecord: nil,
        dmarcPolicy: nil,
        txtRecords: []
    )
    let engine = EmailIntelligenceEngine()
    let original = try await engine.assembleFromData(
        domain: "example.com",
        dns: dns,
        smtp: nil
    )

    let encoder = JSONEncoder()
    let data = try encoder.encode(original)
    let decoded = try JSONDecoder().decode(EmailIntelligence.self, from: data)

    #expect(decoded.domain == original.domain)
    #expect(decoded.classification?.isWebmail == original.classification?.isWebmail)
    #expect(decoded.dns.spfRecord == original.dns.spfRecord)
}

// MARK: - Version

@Test func versionBumpedTo020() {
    #expect(EmailIntel.version == "0.2.0")
}
