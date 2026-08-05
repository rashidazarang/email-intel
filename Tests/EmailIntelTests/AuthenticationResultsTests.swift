import Testing
import Foundation
@testable import EmailIntel

// MARK: - Full Authentication-Results

@Test func fullAuthenticationResults() {
    let header = "mx.google.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass"
    let result = AuthenticationResultsParser.parse(header)
    #expect(result != nil)
    #expect(result?.authservId == "mx.google.com")
    #expect(result?.results.count == 3)

    let spf = result?.results.first { $0.method == "spf" }
    #expect(spf?.result == "pass")
    #expect(spf?.detail == "smtp.mailfrom=example.com")

    let dkim = result?.results.first { $0.method == "dkim" }
    #expect(dkim?.result == "pass")
    #expect(dkim?.detail == "header.d=example.com")

    let dmarc = result?.results.first { $0.method == "dmarc" }
    #expect(dmarc?.result == "pass")
}

// MARK: - Failed Results

@Test func failedAuthResults() {
    let header = "mx.example.com; spf=softfail smtp.mailfrom=spammer.com; dkim=fail; dmarc=fail"
    let result = AuthenticationResultsParser.parse(header)
    #expect(result != nil)
    #expect(result?.results.count == 3)

    let spf = result?.results.first { $0.method == "spf" }
    #expect(spf?.result == "softfail")

    let dkim = result?.results.first { $0.method == "dkim" }
    #expect(dkim?.result == "fail")

    let dmarc = result?.results.first { $0.method == "dmarc" }
    #expect(dmarc?.result == "fail")
}

// MARK: - Detail Strings

@Test func authResultWithDetail() {
    let header = "mx.example.com; spf=pass smtp.mailfrom=user@example.com"
    let result = AuthenticationResultsParser.parse(header)
    #expect(result != nil)

    let spf = result?.results.first { $0.method == "spf" }
    #expect(spf?.result == "pass")
    #expect(spf?.detail == "smtp.mailfrom=user@example.com")
}

// MARK: - Parenthesized Reason

@Test func authResultWithReason() {
    let header = "mx.example.com; dkim=fail (bad signature) header.d=example.com"
    let result = AuthenticationResultsParser.parse(header)
    #expect(result != nil)

    let dkim = result?.results.first { $0.method == "dkim" }
    #expect(dkim?.result == "fail")
    #expect(dkim?.reason == "bad signature")
    #expect(dkim?.detail == "header.d=example.com")
}

@Test func authResultWithReasonNoDetail() {
    let header = "mx.example.com; dkim=fail (body hash did not verify)"
    let result = AuthenticationResultsParser.parse(header)
    let dkim = result?.results.first { $0.method == "dkim" }
    #expect(dkim?.result == "fail")
    #expect(dkim?.reason == "body hash did not verify")
}

// MARK: - Missing Methods

@Test func authResultSPFOnly() {
    let header = "mx.example.com; spf=pass"
    let result = AuthenticationResultsParser.parse(header)
    #expect(result?.results.count == 1)
    #expect(result?.results[0].method == "spf")
    #expect(result?.results[0].result == "pass")
}

@Test func authResultNone() {
    let header = "mx.example.com; none"
    let result = AuthenticationResultsParser.parse(header)
    #expect(result != nil)
    #expect(result?.results.isEmpty == true)
}

// MARK: - ARC Header Sets (via full parser)

@Test func arcHeaderSetParsing() {
    let raw = """
    ARC-Authentication-Results: i=1; mx.google.com; spf=pass; dkim=pass
    ARC-Message-Signature: i=1; a=rsa-sha256; d=google.com; s=arc-20160816
    ARC-Seal: i=1; a=rsa-sha256; d=google.com; s=arc-20160816; cv=none
    """
    let analysis = EmailHeaderParser.parse(rawHeaders: raw)
    #expect(analysis.arcSets.count == 1)
    #expect(analysis.arcSets[0].instance == 1)
    #expect(analysis.arcSets[0].authenticationResults.contains("spf=pass"))
    #expect(analysis.arcSets[0].messageSignature.contains("rsa-sha256"))
    #expect(analysis.arcSets[0].seal.contains("cv=none"))
}

@Test func arcMultipleInstances() {
    let raw = """
    ARC-Authentication-Results: i=2; mx.relay.com; spf=pass
    ARC-Message-Signature: i=2; a=rsa-sha256; d=relay.com; s=arc
    ARC-Seal: i=2; a=rsa-sha256; d=relay.com; cv=pass
    ARC-Authentication-Results: i=1; mx.google.com; dkim=pass
    ARC-Message-Signature: i=1; a=rsa-sha256; d=google.com; s=arc
    ARC-Seal: i=1; a=rsa-sha256; d=google.com; cv=none
    """
    let analysis = EmailHeaderParser.parse(rawHeaders: raw)
    #expect(analysis.arcSets.count == 2)
    // Sorted by instance number
    #expect(analysis.arcSets[0].instance == 1)
    #expect(analysis.arcSets[1].instance == 2)
}

// MARK: - List Headers

@Test func listHeaderExtraction() {
    let raw = """
    List-Unsubscribe: <mailto:unsub@example.com>, <https://example.com/unsub>
    List-Id: <dev.example.com>
    List-Post: <mailto:dev@example.com>
    List-Archive: <https://example.com/archive>
    Subject: Test
    """
    let analysis = EmailHeaderParser.parse(rawHeaders: raw)
    #expect(analysis.listHeaders["list-unsubscribe"] != nil)
    #expect(analysis.listHeaders["list-id"] == "<dev.example.com>")
    #expect(analysis.listHeaders["list-post"] == "<mailto:dev@example.com>")
    #expect(analysis.listHeaders["list-archive"] == "<https://example.com/archive>")
    #expect(analysis.listHeaders.count == 4)
}

// MARK: - X-Mailer Extraction

@Test func xMailerExtraction() {
    let raw = """
    X-Mailer: Apple Mail (2.3654.120.2)
    Subject: Hello
    """
    let analysis = EmailHeaderParser.parse(rawHeaders: raw)
    #expect(analysis.clientInfo != nil)
    #expect(analysis.clientInfo?.mailer == "Apple Mail (2.3654.120.2)")
}

@Test func userAgentExtraction() {
    let raw = """
    User-Agent: Thunderbird 115.0
    Subject: Hello
    """
    let analysis = EmailHeaderParser.parse(rawHeaders: raw)
    #expect(analysis.clientInfo != nil)
    #expect(analysis.clientInfo?.userAgent == "Thunderbird 115.0")
}

@Test func noClientInfoWhenAbsent() {
    let raw = """
    Subject: Hello
    From: user@example.com
    """
    let analysis = EmailHeaderParser.parse(rawHeaders: raw)
    #expect(analysis.clientInfo == nil)
}

// MARK: - Return-Path

@Test func returnPathExtraction() {
    let raw = """
    Return-Path: <bounce@example.com>
    Subject: Test
    """
    let analysis = EmailHeaderParser.parse(rawHeaders: raw)
    #expect(analysis.returnPath == "bounce@example.com")
}

@Test func returnPathWithoutAngleBrackets() {
    let raw = """
    Return-Path: bounce@example.com
    Subject: Test
    """
    let analysis = EmailHeaderParser.parse(rawHeaders: raw)
    #expect(analysis.returnPath == "bounce@example.com")
}

// MARK: - Multiple Authentication-Results Headers

@Test func multipleAuthResultsHeaders() {
    let raw = """
    Authentication-Results: mx1.example.com; spf=pass
    Authentication-Results: mx2.example.com; dkim=pass header.d=example.com
    """
    let analysis = EmailHeaderParser.parse(rawHeaders: raw)
    #expect(analysis.authenticationResults.count == 2)
    #expect(analysis.authenticationResults[0].authservId == "mx1.example.com")
    #expect(analysis.authenticationResults[1].authservId == "mx2.example.com")
}

// MARK: - Edge Cases

@Test func emptyHeadersProducesEmptyAnalysis() {
    let analysis = EmailHeaderParser.parse(rawHeaders: "")
    #expect(analysis.receivedChain.isEmpty)
    #expect(analysis.authenticationResults.isEmpty)
    #expect(analysis.arcSets.isEmpty)
    #expect(analysis.clientInfo == nil)
    #expect(analysis.listHeaders.isEmpty)
    #expect(analysis.returnPath == nil)
    #expect(analysis.originatingIP == nil)
    #expect(analysis.estimatedDeliverySeconds == nil)
}

@Test func headerNameMatchingIsCaseInsensitive() {
    let raw = """
    RECEIVED: from a.example.com by b.example.com; Fri, 10 Apr 2026 14:30:00 +0000
    x-MAILER: TestClient 1.0
    RETURN-PATH: <test@example.com>
    """
    let analysis = EmailHeaderParser.parse(rawHeaders: raw)
    #expect(analysis.receivedChain.count == 1)
    #expect(analysis.clientInfo?.mailer == "TestClient 1.0")
    #expect(analysis.returnPath == "test@example.com")
}

// MARK: - Comment attached to the result with no separating space

@Test func resultWithAttachedPolicyComment() {
    // Yahoo's real Authentication-Results. RFC 5322 CFWS does not require a space
    // before a comment, so the policy annotation sits flush against the result.
    // Parsed by whitespace alone, the result became "pass(p=QUARANTINE)" and every
    // consumer comparing against "pass" read a PASS as a failure.
    let header = "atlas.yahoo.com; dkim=pass header.i=@example.com; spf=pass smtp.mailfrom=send.example.com; dmarc=pass(p=QUARANTINE)"
    let result = AuthenticationResultsParser.parse(header)
    #expect(result != nil)

    let dmarc = result?.results.first { $0.method == "dmarc" }
    #expect(dmarc?.result == "pass")
    #expect(dmarc?.reason == "p=QUARANTINE")

    let spf = result?.results.first { $0.method == "spf" }
    #expect(spf?.result == "pass")

    let dkim = result?.results.first { $0.method == "dkim" }
    #expect(dkim?.result == "pass")
}

@Test func attachedCommentDoesNotRescueAFailure() {
    // The annotation must not smuggle a failure through as something else.
    let header = "atlas.yahoo.com; dmarc=fail(p=REJECT); spf=softfail(mechanism)"
    let result = AuthenticationResultsParser.parse(header)

    let dmarc = result?.results.first { $0.method == "dmarc" }
    #expect(dmarc?.result == "fail")
    #expect(dmarc?.reason == "p=REJECT")

    let spf = result?.results.first { $0.method == "spf" }
    #expect(spf?.result == "softfail")
    #expect(spf?.reason == "mechanism")
}

@Test func spacedAndAttachedCommentsParseIdentically() {
    let spaced = AuthenticationResultsParser.parse("mx.test; dmarc=pass (p=NONE)")
    let attached = AuthenticationResultsParser.parse("mx.test; dmarc=pass(p=NONE)")
    let a = spaced?.results.first { $0.method == "dmarc" }
    let b = attached?.results.first { $0.method == "dmarc" }
    #expect(a?.result == b?.result)
    #expect(a?.reason == b?.reason)
    #expect(b?.result == "pass")
}
