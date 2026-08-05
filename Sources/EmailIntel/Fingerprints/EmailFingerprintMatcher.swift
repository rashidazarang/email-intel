import Foundation

public struct EmailFingerprintMatcher: Sendable {
    public static func match(
        spfRecord: String? = nil,
        mxHosts: [String] = [],
        dkimSelectors: [String] = [],
        txtRecords: [String] = [],
        fingerprints: [EmailServiceFingerprint]
    ) -> [EmailProvider] {
        let spfLower = spfRecord?.lowercased()
        let mxLower = mxHosts.map { $0.lowercased() }
        let dkimLower = dkimSelectors.map { $0.lowercased() }
        let txtLower = txtRecords.map { $0.lowercased() }

        var results: [EmailProvider] = []

        for fp in fingerprints {
            var score = 0
            var signals: [String] = []

            // SPF includes (substring match, weight 30)
            if let spf = spfLower {
                for include in fp.signals.spfIncludes {
                    if spf.contains(include.lowercased()) {
                        score += 30
                        signals.append("spf:\(include)")
                        break
                    }
                }
            }

            // DKIM selectors (exact match, weight 30)
            for selector in fp.signals.dkimSelectors {
                if dkimLower.contains(selector.lowercased()) {
                    score += 30
                    signals.append("dkim:\(selector)")
                    break
                }
            }

            // MX patterns (substring match, weight 25)
            for pattern in fp.signals.mxPatterns {
                let patLower = pattern.lowercased()
                if mxLower.contains(where: { $0.contains(patLower) }) {
                    score += 25
                    signals.append("mx:\(pattern)")
                    break
                }
            }

            // TXT verification (prefix match, weight 15)
            for prefix in fp.signals.txtVerification {
                let prefLower = prefix.lowercased()
                if txtLower.contains(where: { $0.hasPrefix(prefLower) }) {
                    score += 15
                    signals.append("txt:\(prefix)")
                    break
                }
            }

            if score > 0 {
                results.append(EmailProvider(
                    id: fp.id,
                    name: fp.name,
                    category: fp.category,
                    confidence: score,
                    matchedSignals: signals
                ))
            }
        }

        return results.sorted { $0.confidence > $1.confidence }
    }
}
