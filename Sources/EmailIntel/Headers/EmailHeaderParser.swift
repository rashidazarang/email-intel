import Foundation
import os

public struct EmailHeaderParser: Sendable {

    private static let logger = Logger(subsystem: "com.rashidazarang.emailintel", category: "HeaderParser")

    private static let arcInstanceRegex: NSRegularExpression? =
        try? NSRegularExpression(pattern: "\\bi=(\\d+)")

    public static func parse(rawHeaders: String) -> EmailHeaderAnalysis {
        guard !rawHeaders.isEmpty else {
            return EmailHeaderAnalysis(
                receivedChain: [],
                authenticationResults: [],
                arcSets: [],
                clientInfo: nil,
                listHeaders: [:],
                returnPath: nil,
                originatingIP: nil,
                estimatedDeliverySeconds: nil
            )
        }

        let headers = unfoldHeaders(rawHeaders)

        var receivedValues: [String] = []
        var authResults: [AuthenticationResult] = []
        var arcAuthResults: [(Int, String)] = []
        var arcMessageSigs: [(Int, String)] = []
        var arcSeals: [(Int, String)] = []
        var listHeaders: [String: String] = [:]
        var mailer: String?
        var userAgent: String?
        var returnPath: String?

        for (name, value) in headers {
            let lowerName = name.lowercased()

            switch lowerName {
            case "received":
                receivedValues.append(value)
            case "authentication-results":
                if let result = AuthenticationResultsParser.parse(value) {
                    authResults.append(result)
                }
            case "arc-authentication-results":
                if let instance = extractARCInstance(from: value) {
                    arcAuthResults.append((instance, value))
                }
            case "arc-message-signature":
                if let instance = extractARCInstance(from: value) {
                    arcMessageSigs.append((instance, value))
                }
            case "arc-seal":
                if let instance = extractARCInstance(from: value) {
                    arcSeals.append((instance, value))
                }
            case "x-mailer":
                mailer = value
            case "user-agent":
                userAgent = value
            case "return-path":
                var rp = value.trimmingCharacters(in: .whitespaces)
                if rp.hasPrefix("<"), rp.hasSuffix(">") {
                    rp = String(rp.dropFirst().dropLast())
                }
                returnPath = rp
            default:
                if lowerName.hasPrefix("list-") {
                    listHeaders[lowerName] = value
                }
            }
        }

        let receivedChain = receivedValues.map { ReceivedChainAnalyzer.analyze($0) }

        let originatingIP = receivedValues.last.flatMap { ReceivedChainAnalyzer.extractIP(from: $0) }

        let timestamps = receivedChain.compactMap { $0.timestamp }
        let estimatedDeliverySeconds: Double?
        if timestamps.count >= 2,
           let oldest = timestamps.min(),
           let newest = timestamps.max() {
            estimatedDeliverySeconds = newest.timeIntervalSince(oldest)
        } else {
            estimatedDeliverySeconds = nil
        }

        let arcSets = buildARCSets(
            authResults: arcAuthResults,
            messageSigs: arcMessageSigs,
            seals: arcSeals
        )

        let clientInfo: ClientInfo?
        if mailer != nil || userAgent != nil {
            clientInfo = ClientInfo(mailer: mailer, userAgent: userAgent)
        } else {
            clientInfo = nil
        }

        return EmailHeaderAnalysis(
            receivedChain: receivedChain,
            authenticationResults: authResults,
            arcSets: arcSets,
            clientInfo: clientInfo,
            listHeaders: listHeaders,
            returnPath: returnPath,
            originatingIP: originatingIP,
            estimatedDeliverySeconds: estimatedDeliverySeconds
        )
    }

    // MARK: - Header Unfolding

    private static func unfoldHeaders(_ raw: String) -> [(name: String, value: String)] {
        let lines = raw.components(separatedBy: "\n").map { line -> String in
            var l = line
            if l.hasSuffix("\r") {
                l = String(l.dropLast())
            }
            return l
        }

        var foldedLines: [String] = []
        for line in lines {
            if line.isEmpty { continue }
            if let first = line.first, first == " " || first == "\t" {
                if !foldedLines.isEmpty {
                    let trimmed = String(line.drop(while: { $0 == " " || $0 == "\t" }))
                    foldedLines[foldedLines.count - 1] += " " + trimmed
                }
            } else {
                foldedLines.append(line)
            }
        }

        var headers: [(name: String, value: String)] = []
        for line in foldedLines {
            guard let colonIdx = line.firstIndex(of: ":") else { continue }
            let name = String(line[line.startIndex..<colonIdx]).trimmingCharacters(in: .whitespaces)
            let value = String(line[line.index(after: colonIdx)...]).trimmingCharacters(in: .whitespaces)
            guard !name.isEmpty else { continue }
            headers.append((name: name, value: value))
        }

        return headers
    }

    // MARK: - ARC Helpers

    private static func extractARCInstance(from value: String) -> Int? {
        guard let regex = arcInstanceRegex else { return nil }
        let nsRange = NSRange(value.startIndex..., in: value)
        guard let match = regex.firstMatch(in: value, range: nsRange),
              let numRange = Range(match.range(at: 1), in: value) else {
            return nil
        }
        return Int(value[numRange])
    }

    private static func buildARCSets(
        authResults: [(Int, String)],
        messageSigs: [(Int, String)],
        seals: [(Int, String)]
    ) -> [ARCHeaderSet] {
        var instances = Set<Int>()
        for (i, _) in authResults { instances.insert(i) }
        for (i, _) in messageSigs { instances.insert(i) }
        for (i, _) in seals { instances.insert(i) }

        return instances.sorted().map { instance in
            ARCHeaderSet(
                instance: instance,
                authenticationResults: authResults.first { $0.0 == instance }?.1 ?? "",
                messageSignature: messageSigs.first { $0.0 == instance }?.1 ?? "",
                seal: seals.first { $0.0 == instance }?.1 ?? ""
            )
        }
    }
}
