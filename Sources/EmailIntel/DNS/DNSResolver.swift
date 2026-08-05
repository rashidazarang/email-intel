import Foundation
import os

/// DNS-over-HTTPS resolver using Cloudflare's JSON API.
///
/// All queries go through `https://cloudflare-dns.com/dns-query` with
/// `Accept: application/dns-json`. No external dependencies — pure URLSession.
public actor DNSResolver {

    private let session: URLSession
    private let logger = Logger(subsystem: "com.rashidazarang.emailintel", category: "DNSResolver")

    private static let baseURL = "https://cloudflare-dns.com/dns-query"

    // Cloudflare DNS record type numbers
    private enum RecordType: Int, Sendable {
        case a = 1
        case mx = 15
        case txt = 16
    }

    public init(session: URLSession = .shared) {
        self.session = session
    }

    // MARK: - Public API

    /// Resolves TXT records for a domain. Multi-string TXT records are
    /// concatenated per RFC 7208 §3.3.
    public func resolveTXT(domain: String) async throws -> [String] {
        let response = try await query(domain: domain, type: .txt)
        return response.answer
            .filter { $0.type == RecordType.txt.rawValue }
            .map { DNSRecordParser.stripTXTQuotes($0.data) }
    }

    /// Resolves MX records for a domain. Returns host names sorted by
    /// preference (lowest first), with trailing dots stripped and lowercased.
    public func resolveMX(domain: String) async throws -> [String] {
        let response = try await query(domain: domain, type: .mx)
        return response.answer
            .filter { $0.type == RecordType.mx.rawValue }
            .sorted { $0.mxPreference < $1.mxPreference }
            .map { parseMXHost($0.data) }
    }

    /// Resolves A records for a domain. Returns IPv4 addresses as strings.
    public func resolveA(domain: String) async throws -> [String] {
        let response = try await query(domain: domain, type: .a)
        return response.answer
            .filter { $0.type == RecordType.a.rawValue }
            .map { $0.data }
    }

    // MARK: - Private

    private func query(domain: String, type: RecordType) async throws -> CloudflareResponse {
        guard var components = URLComponents(string: Self.baseURL) else {
            throw DNSError.invalidURL
        }
        components.queryItems = [
            URLQueryItem(name: "name", value: domain),
            URLQueryItem(name: "type", value: String(type.rawValue))
        ]
        guard let url = components.url else {
            throw DNSError.invalidURL
        }

        var request = URLRequest(url: url)
        request.setValue("application/dns-json", forHTTPHeaderField: "Accept")

        logger.debug("Querying \(domain) type=\(type.rawValue)")

        let (data, urlResponse) = try await session.data(for: request)

        guard let httpResponse = urlResponse as? HTTPURLResponse else {
            throw DNSError.unexpectedResponse
        }
        guard httpResponse.statusCode == 200 else {
            logger.error("Non-200 status: \(httpResponse.statusCode) for \(domain)")
            throw DNSError.httpError(statusCode: httpResponse.statusCode)
        }

        let decoded = try JSONDecoder().decode(CloudflareResponse.self, from: data)
        if decoded.status != 0 {
            logger.warning("DNS status \(decoded.status) for \(domain)")
        }
        return decoded
    }

    /// Extracts the host portion from MX record data (e.g. "10 mail.example.com.").
    private func parseMXHost(_ data: String) -> String {
        // MX data from Cloudflare is formatted as "preference host."
        let parts = data.split(separator: " ", maxSplits: 1)
        let host = parts.count > 1 ? String(parts[1]) : data
        return DNSRecordParser.normalizeMXHost(host)
    }
}

// MARK: - Cloudflare JSON Response Model

private struct CloudflareResponse: Decodable, Sendable {
    let status: Int
    let answer: [AnswerRecord]

    enum CodingKeys: String, CodingKey {
        case status = "Status"
        case answer = "Answer"
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.status = try container.decode(Int.self, forKey: .status)
        self.answer = try container.decodeIfPresent([AnswerRecord].self, forKey: .answer) ?? []
    }
}

private struct AnswerRecord: Decodable, Sendable {
    let name: String
    let type: Int
    let data: String

    /// For MX records, extracts the preference value from the data field.
    var mxPreference: Int {
        guard type == 15 else { return 0 }
        let parts = data.split(separator: " ", maxSplits: 1)
        return parts.first.flatMap { Int($0) } ?? 0
    }
}

// MARK: - Errors

public enum DNSError: Error, Sendable {
    case invalidURL
    case unexpectedResponse
    case httpError(statusCode: Int)
}
