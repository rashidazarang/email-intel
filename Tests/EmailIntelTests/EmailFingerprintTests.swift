import Testing
@testable import EmailIntel

// MARK: - Database Loading

@Test func databaseLoadsFromBundle() async throws {
    let fingerprints = try await EmailFingerprintDatabase.shared.allFingerprints()
    #expect(fingerprints.count >= 30, "Expected at least 30 services, got \(fingerprints.count)")
}

@Test func databaseLookupByName() async throws {
    let google = try await EmailFingerprintDatabase.shared.fingerprint(named: "google-workspace")
    #expect(google != nil)
    #expect(google?.name == "Google Workspace")
    #expect(google?.category == .mailboxProvider)
}

@Test func databaseLookupMissingReturnsNil() async throws {
    let missing = try await EmailFingerprintDatabase.shared.fingerprint(named: "nonexistent-service")
    #expect(missing == nil)
}

// MARK: - Google Workspace Detection

@Test func googleWorkspaceFullMatch() async throws {
    let fps = try await EmailFingerprintDatabase.shared.allFingerprints()
    let results = EmailFingerprintMatcher.match(
        spfRecord: "v=spf1 include:_spf.google.com ~all",
        mxHosts: ["alt1.aspmx.l.google.com", "aspmx.l.google.com"],
        dkimSelectors: ["google"],
        fingerprints: fps
    )
    let google = results.first { $0.id == "google-workspace" }
    #expect(google != nil)
    // SPF(30) + DKIM(30) + MX(25) = 85
    #expect(google?.confidence == 85)
    #expect(google?.matchedSignals.contains(where: { $0.hasPrefix("spf:") }) == true)
    #expect(google?.matchedSignals.contains(where: { $0.hasPrefix("dkim:") }) == true)
    #expect(google?.matchedSignals.contains(where: { $0.hasPrefix("mx:") }) == true)
}

@Test func googleWorkspaceSPFOnly() async throws {
    let fps = try await EmailFingerprintDatabase.shared.allFingerprints()
    let results = EmailFingerprintMatcher.match(
        spfRecord: "v=spf1 include:_spf.google.com ~all",
        fingerprints: fps
    )
    let google = results.first { $0.id == "google-workspace" }
    #expect(google != nil)
    #expect(google?.confidence == 30) // SPF only
}

// MARK: - Microsoft 365 Detection

@Test func microsoft365Detection() async throws {
    let fps = try await EmailFingerprintDatabase.shared.allFingerprints()
    let results = EmailFingerprintMatcher.match(
        spfRecord: "v=spf1 include:spf.protection.outlook.com -all",
        mxHosts: ["contoso-com.mail.protection.outlook.com"],
        dkimSelectors: ["selector1"],
        fingerprints: fps
    )
    let ms = results.first { $0.id == "microsoft-365" }
    #expect(ms != nil)
    // SPF(30) + DKIM(30) + MX(25) = 85
    #expect(ms?.confidence == 85)
    #expect(ms?.category == .mailboxProvider)
}

// MARK: - SendGrid Detection

@Test func sendGridDetection() async throws {
    let fps = try await EmailFingerprintDatabase.shared.allFingerprints()
    let results = EmailFingerprintMatcher.match(
        spfRecord: "v=spf1 include:sendgrid.net ~all",
        dkimSelectors: ["s1"],
        fingerprints: fps
    )
    let sg = results.first { $0.id == "sendgrid" }
    #expect(sg != nil)
    // SPF(30) + DKIM(30) = 60
    #expect(sg?.confidence == 60)
    #expect(sg?.category == .transactional)
}

@Test func sendGridS2Selector() async throws {
    let fps = try await EmailFingerprintDatabase.shared.allFingerprints()
    let results = EmailFingerprintMatcher.match(
        dkimSelectors: ["s2"],
        fingerprints: fps
    )
    let sg = results.first { $0.id == "sendgrid" }
    #expect(sg != nil)
    #expect(sg?.confidence == 30)
}

// MARK: - Resend Detection

@Test func resendDetectionFromDKIMSelector() async throws {
    let fps = try await EmailFingerprintDatabase.shared.allFingerprints()
    let results = EmailFingerprintMatcher.match(
        dkimSelectors: ["resend"],
        fingerprints: fps
    )
    let resend = results.first { $0.id == "resend" }
    #expect(resend != nil)
    #expect(resend?.confidence == 30)
    #expect(resend?.category == .transactional)
}

@Test func resendDetectionStaysSeparateFromUnderlyingSESInfrastructure() async throws {
    let fps = try await EmailFingerprintDatabase.shared.allFingerprints()
    let results = EmailFingerprintMatcher.match(
        spfRecord: "v=spf1 include:amazonses.com ~all",
        dkimSelectors: ["resend"],
        fingerprints: fps
    )
    let resend = results.first { $0.id == "resend" }
    let ses = results.first { $0.id == "amazon-ses" }
    #expect(resend != nil)
    #expect(resend?.confidence == 30)
    #expect(ses?.confidence == 30)
}

// MARK: - Mailchimp Detection

@Test func mailchimpDetection() async throws {
    let fps = try await EmailFingerprintDatabase.shared.allFingerprints()
    let results = EmailFingerprintMatcher.match(
        spfRecord: "v=spf1 include:servers.mcsv.net ~all",
        dkimSelectors: ["k1"],
        fingerprints: fps
    )
    let mc = results.first { $0.id == "mailchimp" }
    #expect(mc != nil)
    // SPF(30) + DKIM(30) = 60
    #expect(mc?.confidence == 60)
    #expect(mc?.category == .marketing)
}

@Test func mailchimpK1DoesNotMatchMailgun() async throws {
    let fps = try await EmailFingerprintDatabase.shared.allFingerprints()
    let results = EmailFingerprintMatcher.match(
        dkimSelectors: ["k1"],
        fingerprints: fps
    )
    // k1 should match Mailchimp, NOT Mailgun (removed to avoid collision)
    let mailgun = results.first { $0.id == "mailgun" }
    #expect(mailgun == nil)
    let mailchimp = results.first { $0.id == "mailchimp" }
    #expect(mailchimp != nil)
}

// MARK: - HubSpot Detection

@Test func hubspotSig1Selector() async throws {
    let fps = try await EmailFingerprintDatabase.shared.allFingerprints()
    let results = EmailFingerprintMatcher.match(
        dkimSelectors: ["sig1"],
        fingerprints: fps
    )
    let hs = results.first { $0.id == "hubspot" }
    #expect(hs != nil)
    #expect(hs?.confidence == 30)
}

// MARK: - Salesforce Marketing Cloud

@Test func salesforceMarketingCloudDetection() async throws {
    let fps = try await EmailFingerprintDatabase.shared.allFingerprints()
    let results = EmailFingerprintMatcher.match(
        spfRecord: "v=spf1 include:exacttarget.com ~all",
        dkimSelectors: ["sm1"],
        fingerprints: fps
    )
    let sf = results.first { $0.id == "salesforce-marketing" }
    #expect(sf != nil)
    #expect(sf?.confidence == 60)
}

// MARK: - Multiple Services on Same Domain

@Test func multipleServicesDetected() async throws {
    let fps = try await EmailFingerprintDatabase.shared.allFingerprints()
    // Typical enterprise domain: Google Workspace + SendGrid + Mailchimp
    let results = EmailFingerprintMatcher.match(
        spfRecord: "v=spf1 include:_spf.google.com include:sendgrid.net include:servers.mcsv.net ~all",
        mxHosts: ["aspmx.l.google.com"],
        dkimSelectors: ["google", "s1", "k1"],
        fingerprints: fps
    )
    let ids = Set(results.map(\.id))
    #expect(ids.contains("google-workspace"))
    #expect(ids.contains("sendgrid"))
    #expect(ids.contains("mailchimp"))
    #expect(results.count >= 3)
}

// MARK: - No Matches

@Test func noMatchingFingerprintsReturnsEmpty() async throws {
    let fps = try await EmailFingerprintDatabase.shared.allFingerprints()
    let results = EmailFingerprintMatcher.match(
        spfRecord: "v=spf1 include:custom-mail-server.example.com ~all",
        mxHosts: ["mail.example.com"],
        dkimSelectors: ["custom"],
        txtRecords: ["v=spf1 include:custom-mail-server.example.com ~all"],
        fingerprints: fps
    )
    #expect(results.isEmpty)
}

// MARK: - TXT Verification Records

@Test func googleSiteVerification() async throws {
    let fps = try await EmailFingerprintDatabase.shared.allFingerprints()
    let results = EmailFingerprintMatcher.match(
        txtRecords: ["google-site-verification=abc123def456"],
        fingerprints: fps
    )
    let gv = results.first { $0.id == "google-verification" }
    #expect(gv != nil)
    #expect(gv?.category == .verification)
    #expect(gv?.confidence == 15) // TXT only
}

@Test func facebookDomainVerification() async throws {
    let fps = try await EmailFingerprintDatabase.shared.allFingerprints()
    let results = EmailFingerprintMatcher.match(
        txtRecords: ["facebook-domain-verification=xyz789"],
        fingerprints: fps
    )
    let fb = results.first { $0.id == "facebook-verification" }
    #expect(fb != nil)
    #expect(fb?.category == .verification)
}

@Test func multipleTxtVerifications() async throws {
    let fps = try await EmailFingerprintDatabase.shared.allFingerprints()
    let results = EmailFingerprintMatcher.match(
        txtRecords: [
            "google-site-verification=abc",
            "facebook-domain-verification=def",
            "MS=ms12345678",
            "atlassian-domain-verification=ghi",
        ],
        fingerprints: fps
    )
    let ids = Set(results.map(\.id))
    #expect(ids.contains("google-verification"))
    #expect(ids.contains("facebook-verification"))
    #expect(ids.contains("microsoft-verification"))
    #expect(ids.contains("atlassian-verification"))
}

// MARK: - Confidence Scoring

@Test func singleSignalLowerThanMultiSignal() async throws {
    let fps = try await EmailFingerprintDatabase.shared.allFingerprints()

    let singleSignal = EmailFingerprintMatcher.match(
        spfRecord: "v=spf1 include:_spf.google.com ~all",
        fingerprints: fps
    )
    let multiSignal = EmailFingerprintMatcher.match(
        spfRecord: "v=spf1 include:_spf.google.com ~all",
        mxHosts: ["aspmx.l.google.com"],
        dkimSelectors: ["google"],
        fingerprints: fps
    )

    let singleConf = singleSignal.first { $0.id == "google-workspace" }?.confidence ?? 0
    let multiConf = multiSignal.first { $0.id == "google-workspace" }?.confidence ?? 0
    #expect(singleConf < multiConf)
    #expect(singleConf == 30) // SPF only
    #expect(multiConf == 85)  // SPF + DKIM + MX
}

@Test func confidenceCappedAt100() {
    // Manually construct a provider with score exceeding 100
    let provider = EmailProvider(
        id: "test",
        name: "Test",
        category: .other,
        confidence: 150,
        matchedSignals: []
    )
    #expect(provider.confidence == 100)
}

@Test func confidenceFlooredAtZero() {
    let provider = EmailProvider(
        id: "test",
        name: "Test",
        category: .other,
        confidence: -10,
        matchedSignals: []
    )
    #expect(provider.confidence == 0)
}

// MARK: - Sorting

@Test func resultsSortedByConfidenceDescending() async throws {
    let fps = try await EmailFingerprintDatabase.shared.allFingerprints()
    let results = EmailFingerprintMatcher.match(
        spfRecord: "v=spf1 include:_spf.google.com include:sendgrid.net ~all",
        mxHosts: ["aspmx.l.google.com"],
        dkimSelectors: ["google"],
        fingerprints: fps
    )
    // Google should be first (SPF+DKIM+MX=85), SendGrid second (SPF=30)
    #expect(results.count >= 2)
    for i in 0..<(results.count - 1) {
        #expect(results[i].confidence >= results[i + 1].confidence)
    }
}

// MARK: - Security Services

@Test func proofpointDetection() async throws {
    let fps = try await EmailFingerprintDatabase.shared.allFingerprints()
    let results = EmailFingerprintMatcher.match(
        spfRecord: "v=spf1 include:pphosted.com ~all",
        mxHosts: ["mx1.us1.pphosted.com"],
        fingerprints: fps
    )
    let pp = results.first { $0.id == "proofpoint" }
    #expect(pp != nil)
    #expect(pp?.category == .security)
    #expect(pp?.confidence == 55) // SPF(30) + MX(25)
}

@Test func mimecastDetection() async throws {
    let fps = try await EmailFingerprintDatabase.shared.allFingerprints()
    let results = EmailFingerprintMatcher.match(
        spfRecord: "v=spf1 include:mimecast.com ~all",
        mxHosts: ["us-smtp-inbound-1.mimecast.com"],
        fingerprints: fps
    )
    let mc = results.first { $0.id == "mimecast" }
    #expect(mc != nil)
    #expect(mc?.category == .security)
    #expect(mc?.confidence == 55)
}

// MARK: - MX Substring Matching

@Test func mxSubdomainMatching() async throws {
    let fps = try await EmailFingerprintDatabase.shared.allFingerprints()
    // MX pattern "google.com" should match "alt1.aspmx.l.google.com"
    let results = EmailFingerprintMatcher.match(
        mxHosts: ["alt1.aspmx.l.google.com"],
        fingerprints: fps
    )
    let google = results.first { $0.id == "google-workspace" }
    #expect(google != nil)
    #expect(google?.confidence == 25) // MX only
}

// MARK: - Case Insensitivity

@Test func matchingIsCaseInsensitive() async throws {
    let fps = try await EmailFingerprintDatabase.shared.allFingerprints()
    let results = EmailFingerprintMatcher.match(
        spfRecord: "v=spf1 INCLUDE:_SPF.GOOGLE.COM ~all",
        mxHosts: ["ASPMX.L.GOOGLE.COM"],
        dkimSelectors: ["GOOGLE"],
        fingerprints: fps
    )
    let google = results.first { $0.id == "google-workspace" }
    #expect(google != nil)
    #expect(google?.confidence == 85)
}

// MARK: - Service Categories

@Test func allCategoriesRepresented() async throws {
    let fps = try await EmailFingerprintDatabase.shared.allFingerprints()
    let categories = Set(fps.map(\.category))
    #expect(categories.contains(.mailboxProvider))
    #expect(categories.contains(.transactional))
    #expect(categories.contains(.marketing))
    #expect(categories.contains(.security))
    #expect(categories.contains(.verification))
}

// MARK: - Quien DKIM Selector Coverage

@Test func quienDKIMSelectorsCovered() async throws {
    let fps = try await EmailFingerprintDatabase.shared.allFingerprints()
    let allDKIM = fps.flatMap(\.signals.dkimSelectors)

    // All quien selectors that should map to a specific service
    let expectedSelectors = ["google", "selector1", "selector2", "k1", "mandrill", "resend", "s1", "s2", "sm1", "sm2", "sig1"]
    for sel in expectedSelectors {
        #expect(allDKIM.contains(sel), "Missing DKIM selector: \(sel)")
    }
}

// MARK: - Empty Fingerprint Database

@Test func matchWithEmptyFingerprintsReturnsEmpty() {
    let results = EmailFingerprintMatcher.match(
        spfRecord: "v=spf1 include:_spf.google.com ~all",
        mxHosts: ["aspmx.l.google.com"],
        fingerprints: []
    )
    #expect(results.isEmpty)
}
