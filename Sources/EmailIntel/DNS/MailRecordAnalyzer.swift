import Foundation

public struct MailRecordAnalyzer: Sendable {

    // MARK: - SPF

    /// Parses an SPF TXT record into an `SPFRecord`.
    /// Returns `nil` if the record does not start with `v=spf1`.
    public static func parseSPF(_ raw: String) -> SPFRecord? {
        let trimmed = raw.trimmingCharacters(in: .whitespaces)
        guard trimmed.lowercased().hasPrefix("v=spf1") else { return nil }

        let tokens = trimmed.split(separator: " ").map(String.init)
        var mechanisms: [String] = []
        var policy: String?

        for token in tokens.dropFirst() { // skip "v=spf1"
            let lower = token.lowercased()
            if lower == "+all" || lower == "-all" || lower == "~all" || lower == "?all" {
                policy = token
            } else {
                mechanisms.append(token)
            }
        }

        return SPFRecord(raw: trimmed, mechanisms: mechanisms, policy: policy)
    }

    // MARK: - DMARC

    private static let dmarcTagPattern: NSRegularExpression = {
        // Matches tag=value pairs separated by semicolons
        // swiftlint:disable:next force_try
        try! NSRegularExpression(pattern: #"([a-zA-Z]+)\s*=\s*([^;]*)"#)
    }()

    /// Parses a DMARC TXT record into a `DMARCRecord`.
    /// Returns `nil` if the record does not start with `v=DMARC1`.
    public static func parseDMARC(_ raw: String) -> DMARCRecord? {
        let trimmed = raw.trimmingCharacters(in: .whitespaces)
        guard trimmed.lowercased().hasPrefix("v=dmarc1") else { return nil }

        let nsRange = NSRange(trimmed.startIndex..., in: trimmed)
        let matches = dmarcTagPattern.matches(in: trimmed, range: nsRange)

        var tags: [String: String] = [:]
        for match in matches {
            guard let keyRange = Range(match.range(at: 1), in: trimmed),
                  let valRange = Range(match.range(at: 2), in: trimmed) else { continue }
            let key = String(trimmed[keyRange]).trimmingCharacters(in: .whitespaces).lowercased()
            let val = String(trimmed[valRange]).trimmingCharacters(in: .whitespaces)
            tags[key] = val
        }

        let rua = parseURIList(tags["rua"])
        let ruf = parseURIList(tags["ruf"])
        let pct: Int? = tags["pct"].flatMap { Int($0) }

        return DMARCRecord(
            raw: trimmed,
            policy: tags["p"],
            subdomainPolicy: tags["sp"],
            rua: rua,
            ruf: ruf,
            pct: pct
        )
    }

    /// Splits a comma-separated DMARC URI list (e.g. `mailto:a@b,mailto:c@d`).
    private static func parseURIList(_ value: String?) -> [String] {
        guard let value, !value.isEmpty else { return [] }
        return value
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
    }

    // MARK: - DKIM

    private static let dkimTagPattern: NSRegularExpression = {
        // swiftlint:disable:next force_try
        try! NSRegularExpression(pattern: #"([a-zA-Z]+)\s*=\s*([^;]*)"#)
    }()

    /// Returns true when a selector TXT record looks like a DKIM public key.
    /// Some providers, including Resend, publish selector records as `p=...`
    /// without the optional `v=DKIM1` tag.
    public static func isDKIMPublicKeyRecord(_ raw: String) -> Bool {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return false }

        let nsRange = NSRange(trimmed.startIndex..., in: trimmed)
        let matches = dkimTagPattern.matches(in: trimmed, range: nsRange)

        var tags: [String: String] = [:]
        for match in matches {
            guard let keyRange = Range(match.range(at: 1), in: trimmed),
                  let valRange = Range(match.range(at: 2), in: trimmed) else { continue }
            let key = String(trimmed[keyRange]).trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let val = String(trimmed[valRange]).trimmingCharacters(in: .whitespacesAndNewlines)
            tags[key] = val
        }

        let hasPublicKey = tags["p"].map { !$0.isEmpty } ?? false

        return hasPublicKey
    }

    /// Parses a DKIM TXT record for a given selector.
    /// Returns `nil` if the selector record does not look like a DKIM key.
    public static func parseDKIM(selector: String, raw: String) -> DKIMRecord? {
        let trimmed = raw.trimmingCharacters(in: .whitespaces)
        guard isDKIMPublicKeyRecord(trimmed) else { return nil }
        return DKIMRecord(selector: selector, raw: trimmed)
    }

    // MARK: - BIMI

    private static let bimiTagPattern: NSRegularExpression = {
        // swiftlint:disable:next force_try
        try! NSRegularExpression(pattern: #"([a-zA-Z]+)\s*=\s*([^;]*)"#)
    }()

    /// Parses a BIMI TXT record into a `BIMIRecord`.
    /// Returns `nil` if the record does not start with `v=BIMI1`.
    public static func parseBIMI(_ raw: String) -> BIMIRecord? {
        let trimmed = raw.trimmingCharacters(in: .whitespaces)
        guard trimmed.lowercased().hasPrefix("v=bimi1") else { return nil }

        let nsRange = NSRange(trimmed.startIndex..., in: trimmed)
        let matches = bimiTagPattern.matches(in: trimmed, range: nsRange)

        var tags: [String: String] = [:]
        for match in matches {
            guard let keyRange = Range(match.range(at: 1), in: trimmed),
                  let valRange = Range(match.range(at: 2), in: trimmed) else { continue }
            let key = String(trimmed[keyRange]).trimmingCharacters(in: .whitespaces).lowercased()
            let val = String(trimmed[valRange]).trimmingCharacters(in: .whitespaces)
            tags[key] = val
        }

        return BIMIRecord(raw: trimmed, location: tags["l"])
    }
}
