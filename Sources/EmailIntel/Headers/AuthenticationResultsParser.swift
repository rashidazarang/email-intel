import Foundation

public struct AuthenticationResultsParser: Sendable {

    public static func parse(_ header: String) -> AuthenticationResult? {
        let trimmed = header.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return nil }

        let parts = trimmed.components(separatedBy: ";")
        guard let first = parts.first else { return nil }

        let authservId = first.trimmingCharacters(in: .whitespaces)
        guard !authservId.isEmpty else { return nil }

        var results: [AuthenticationMethodResult] = []

        for part in parts.dropFirst() {
            let chunk = part.trimmingCharacters(in: .whitespaces)
            if chunk.isEmpty || chunk.lowercased() == "none" { continue }

            guard let eqIdx = chunk.firstIndex(of: "=") else { continue }
            let method = String(chunk[chunk.startIndex..<eqIdx]).trimmingCharacters(in: .whitespaces)
            guard !method.isEmpty else { continue }

            let afterEq = String(chunk[chunk.index(after: eqIdx)...]).trimmingCharacters(in: .whitespaces)
            // The result token ends at whitespace OR at an opening parenthesis. RFC 5322
            // CFWS does not require a space before a comment, and Yahoo writes
            // `dmarc=pass(p=QUARANTINE)` with none. Splitting on whitespace alone made the
            // whole `pass(p=QUARANTINE)` the result, so a PASS compared unequal to "pass"
            // for every consumer — and the policy was lost instead of landing in `reason`.
            let resultEnd = afterEq.firstIndex(where: { $0 == " " || $0 == "(" }) ?? afterEq.endIndex
            let result = String(afterEq[afterEq.startIndex..<resultEnd])
            guard !result.isEmpty else { continue }

            let remaining = String(afterEq[resultEnd...]).trimmingCharacters(in: .whitespaces)

            var reason: String?
            var detail: String?

            if !remaining.isEmpty {
                if remaining.hasPrefix("(") {
                    if let closeIdx = remaining.firstIndex(of: ")") {
                        let reasonStart = remaining.index(after: remaining.startIndex)
                        reason = String(remaining[reasonStart..<closeIdx])
                        let afterClose = remaining.index(after: closeIdx)
                        if afterClose < remaining.endIndex {
                            let afterReason = String(remaining[afterClose...])
                                .trimmingCharacters(in: .whitespaces)
                            detail = afterReason.isEmpty ? nil : afterReason
                        }
                    }
                } else {
                    detail = remaining
                }
            }

            results.append(AuthenticationMethodResult(
                method: method,
                result: result,
                detail: detail,
                reason: reason
            ))
        }

        return AuthenticationResult(authservId: authservId, results: results)
    }
}
