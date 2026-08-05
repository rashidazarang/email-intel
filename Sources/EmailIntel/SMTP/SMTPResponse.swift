import Foundation

public struct SMTPResponse: Sendable {
    public let code: Int
    public let lines: [String]

    public init(code: Int, lines: [String]) {
        self.code = code
        self.lines = lines
    }

    public static func parseGreeting(_ raw: String) -> String? {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix("220") else { return nil }
        let dropped = trimmed.dropFirst(3)
        return dropped.trimmingCharacters(in: .whitespaces)
    }

    public static func extractBanner(_ raw: String) -> String? {
        parseGreeting(raw)
    }

    public static func parseEHLO(_ raw: String) -> [String] {
        var extensions: [String] = []
        for line in raw.split(whereSeparator: { $0 == "\n" || $0 == "\r" }) {
            let s = String(line).trimmingCharacters(in: .whitespaces)
            guard s.count >= 4, s.hasPrefix("250") else { continue }
            let idx = s.index(s.startIndex, offsetBy: 4)
            let token = String(s[idx...]).trimmingCharacters(in: .whitespaces)
            if !token.isEmpty { extensions.append(token) }
        }
        return extensions
    }
}
