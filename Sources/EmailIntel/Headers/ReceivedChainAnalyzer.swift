import Foundation

struct ReceivedChainAnalyzer: Sendable {

    private static let ipRegex: NSRegularExpression? =
        try? NSRegularExpression(pattern: "\\[(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\]")

    private static let parenTimezoneRegex: NSRegularExpression? =
        try? NSRegularExpression(pattern: "\\s*\\([^)]*\\)\\s*$")

    static func analyze(_ value: String) -> ReceivedHop {
        let semicolonIdx = value.firstIndex(of: ";")
        let routingPart: String
        let datePart: String?

        if let idx = semicolonIdx {
            routingPart = String(value[value.startIndex..<idx])
            let afterSemicolon = value.index(after: idx)
            datePart = afterSemicolon < value.endIndex
                ? String(value[afterSemicolon...]).trimmingCharacters(in: .whitespaces)
                : nil
        } else {
            routingPart = value
            datePart = nil
        }

        let from = extractFrom(routingPart)
        let by = extractBy(routingPart)

        let lowered = value.lowercased()
        let tlsUsed = lowered.contains("esmtps") || lowered.contains("version=tlsv")

        let timestamp: Date?
        if let dp = datePart, !dp.isEmpty {
            timestamp = parseTimestamp(dp)
        } else {
            timestamp = nil
        }

        return ReceivedHop(from: from, by: by, tlsUsed: tlsUsed, timestamp: timestamp)
    }

    static func extractIP(from value: String) -> String? {
        guard let regex = ipRegex else { return nil }
        let nsRange = NSRange(value.startIndex..., in: value)
        guard let match = regex.firstMatch(in: value, range: nsRange),
              let ipRange = Range(match.range(at: 1), in: value) else {
            return nil
        }
        return String(value[ipRange])
    }

    // MARK: - Private

    private static func extractFrom(_ routing: String) -> String? {
        guard let fromRange = routing.range(of: "from ", options: .caseInsensitive) else {
            return nil
        }
        let contentStart = fromRange.upperBound
        let contentEnd: String.Index

        if let byRange = routing.range(of: " by ", options: .caseInsensitive,
                                        range: contentStart..<routing.endIndex) {
            contentEnd = byRange.lowerBound
        } else {
            contentEnd = routing.endIndex
        }

        let result = String(routing[contentStart..<contentEnd]).trimmingCharacters(in: .whitespaces)
        return result.isEmpty ? nil : result
    }

    private static func extractBy(_ routing: String) -> String? {
        let searchStart: String.Index
        if let byRange = routing.range(of: " by ", options: .caseInsensitive) {
            searchStart = byRange.upperBound
        } else if routing.lowercased().hasPrefix("by ") {
            searchStart = routing.index(routing.startIndex, offsetBy: 3)
        } else {
            return nil
        }

        var endIdx = routing.endIndex
        for keyword in [" with ", " for ", " id "] {
            if let range = routing.range(of: keyword, options: .caseInsensitive,
                                          range: searchStart..<routing.endIndex) {
                if range.lowerBound < endIdx {
                    endIdx = range.lowerBound
                }
            }
        }

        let result = String(routing[searchStart..<endIdx]).trimmingCharacters(in: .whitespaces)
        return result.isEmpty ? nil : result
    }

    private static func parseTimestamp(_ dateStr: String) -> Date? {
        var cleaned = dateStr
        if let regex = parenTimezoneRegex {
            let nsRange = NSRange(cleaned.startIndex..., in: cleaned)
            cleaned = regex.stringByReplacingMatches(in: cleaned, range: nsRange, withTemplate: "")
        }
        cleaned = cleaned.trimmingCharacters(in: .whitespaces)

        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "EEE, d MMM yyyy HH:mm:ss Z"
        return formatter.date(from: cleaned)
    }
}
