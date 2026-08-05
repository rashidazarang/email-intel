import Testing
import Foundation
@testable import EmailIntel

// MARK: - Received Chain Parsing

@Test func receivedChainThreeHops() {
    let raw = """
    Received: from mail-dest.example.com (mail-dest.example.com [10.0.0.3])
     by final.example.com with ESMTPS id abc123;
     Fri, 10 Apr 2026 14:30:00 +0000
    Received: from relay.example.net (relay.example.net [10.0.0.2])
     by mail-dest.example.com with ESMTP id def456;
     Fri, 10 Apr 2026 14:29:55 +0000
    Received: from origin.sender.com (origin.sender.com [203.0.113.42])
     by relay.example.net with ESMTP id ghi789;
     Fri, 10 Apr 2026 14:29:50 +0000
    """
    let analysis = EmailHeaderParser.parse(rawHeaders: raw)
    #expect(analysis.receivedChain.count == 3)

    // First hop in chain is the most recent (reverse chronological)
    #expect(analysis.receivedChain[0].from?.contains("mail-dest.example.com") == true)
    #expect(analysis.receivedChain[0].by?.contains("final.example.com") == true)

    // Last hop is the originator
    #expect(analysis.receivedChain[2].from?.contains("origin.sender.com") == true)
    #expect(analysis.receivedChain[2].by?.contains("relay.example.net") == true)
}

@Test func receivedTLSDetectionESMTPS() {
    let raw = """
    Received: from sender.example.com (sender.example.com [10.0.0.1])
     by receiver.example.com with ESMTPS id xyz;
     Mon, 6 Apr 2026 10:00:00 +0000
    """
    let analysis = EmailHeaderParser.parse(rawHeaders: raw)
    #expect(analysis.receivedChain.count == 1)
    #expect(analysis.receivedChain[0].tlsUsed == true)
}

@Test func receivedTLSDetectionVersion() {
    let raw = """
    Received: from sender.example.com (sender.example.com [10.0.0.1])
     by receiver.example.com with ESMTP (version=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384);
     Mon, 6 Apr 2026 10:00:00 +0000
    """
    let analysis = EmailHeaderParser.parse(rawHeaders: raw)
    #expect(analysis.receivedChain.count == 1)
    #expect(analysis.receivedChain[0].tlsUsed == true)
}

@Test func receivedNoTLS() {
    let raw = """
    Received: from sender.example.com (sender.example.com [10.0.0.1])
     by receiver.example.com with ESMTP id abc;
     Mon, 6 Apr 2026 10:00:00 +0000
    """
    let analysis = EmailHeaderParser.parse(rawHeaders: raw)
    #expect(analysis.receivedChain.count == 1)
    #expect(analysis.receivedChain[0].tlsUsed == false)
}

@Test func receivedTimestampParsing() {
    let raw = """
    Received: from a.example.com by b.example.com; Fri, 10 Apr 2026 14:30:00 +0000
    """
    let analysis = EmailHeaderParser.parse(rawHeaders: raw)
    #expect(analysis.receivedChain.count == 1)
    #expect(analysis.receivedChain[0].timestamp != nil)
}

@Test func receivedTimestampWithParenthesizedTimezone() {
    let raw = """
    Received: from a.example.com by b.example.com; Fri, 10 Apr 2026 14:30:00 +0000 (UTC)
    """
    let analysis = EmailHeaderParser.parse(rawHeaders: raw)
    #expect(analysis.receivedChain[0].timestamp != nil)
}

// MARK: - Header Continuation Line Folding

@Test func headerContinuationLineFolding() {
    let raw = """
    Received: from sender.example.com (sender.example.com [10.0.0.1])
    \tby receiver.example.com with ESMTPS id abc;
    \tFri, 10 Apr 2026 14:30:00 +0000
    Subject: Test message
    """
    let analysis = EmailHeaderParser.parse(rawHeaders: raw)
    // The continuation lines should be folded into one Received header
    #expect(analysis.receivedChain.count == 1)
    #expect(analysis.receivedChain[0].by?.contains("receiver.example.com") == true)
    #expect(analysis.receivedChain[0].tlsUsed == true)
}

@Test func headerContinuationWithSpaces() {
    let raw = "Authentication-Results: mx.google.com;\r\n spf=pass smtp.mailfrom=example.com;\r\n dkim=pass header.d=example.com"
    let analysis = EmailHeaderParser.parse(rawHeaders: raw)
    #expect(analysis.authenticationResults.count == 1)
    #expect(analysis.authenticationResults[0].results.count == 2)
}

// MARK: - Originating IP Extraction

@Test func originatingIPFromLastHop() {
    let raw = """
    Received: from relay.example.com (relay.example.com [10.0.0.2])
     by dest.example.com with ESMTP; Fri, 10 Apr 2026 14:30:00 +0000
    Received: from origin.example.com (origin.example.com [203.0.113.42])
     by relay.example.com with ESMTP; Fri, 10 Apr 2026 14:29:55 +0000
    """
    let analysis = EmailHeaderParser.parse(rawHeaders: raw)
    #expect(analysis.originatingIP == "203.0.113.42")
}

@Test func originatingIPFromBracketedAddress() {
    let raw = """
    Received: from unknown ([198.51.100.7]) by mx.example.com; Mon, 6 Apr 2026 10:00:00 +0000
    """
    let analysis = EmailHeaderParser.parse(rawHeaders: raw)
    #expect(analysis.originatingIP == "198.51.100.7")
}

// MARK: - Delivery Time Estimation

@Test func deliveryTimeEstimation() {
    let raw = """
    Received: from b.example.com by c.example.com; Fri, 10 Apr 2026 14:30:10 +0000
    Received: from a.example.com by b.example.com; Fri, 10 Apr 2026 14:30:00 +0000
    """
    let analysis = EmailHeaderParser.parse(rawHeaders: raw)
    #expect(analysis.estimatedDeliverySeconds != nil)
    // 10 seconds between hops
    #expect(analysis.estimatedDeliverySeconds == 10.0)
}

@Test func deliveryTimeNilForSingleHop() {
    let raw = """
    Received: from a.example.com by b.example.com; Fri, 10 Apr 2026 14:30:00 +0000
    """
    let analysis = EmailHeaderParser.parse(rawHeaders: raw)
    // Need at least 2 timestamps to estimate delivery time
    #expect(analysis.estimatedDeliverySeconds == nil)
}
