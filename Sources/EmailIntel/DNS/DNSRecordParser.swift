import Foundation

public struct DNSRecordParser: Sendable {

    /// Strips surrounding quotes from individual TXT strings and concatenates
    /// multi-string TXT records per RFC 7208 §3.3.
    public static func stripTXTQuotes(_ raw: String) -> String {
        // Cloudflare JSON API returns TXT data as: "part1" "part2"
        // We need to strip the quotes and concatenate without extra spaces.
        var result = ""
        var inQuote = false
        for char in raw {
            if char == "\"" {
                inQuote.toggle()
            } else if inQuote {
                result.append(char)
            }
        }
        // If no quotes were found, the string is already bare.
        if result.isEmpty && !raw.isEmpty && !raw.contains("\"") {
            return raw.trimmingCharacters(in: .whitespaces)
        }
        return result
    }

    /// Lowercases and strips the trailing dot from an MX host.
    public static func normalizeMXHost(_ raw: String) -> String {
        var host = raw.trimmingCharacters(in: .whitespaces).lowercased()
        if host.hasSuffix(".") {
            host = String(host.dropLast())
        }
        return host
    }
}
