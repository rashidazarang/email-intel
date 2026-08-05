import Foundation
import os

public actor EmailFingerprintDatabase {
    public static let shared = EmailFingerprintDatabase()

    private var cached: [EmailServiceFingerprint]?
    private let logger = Logger(subsystem: "EmailIntel", category: "FingerprintDatabase")

    private init() {}

    public func allFingerprints() async throws -> [EmailServiceFingerprint] {
        if let cached {
            return cached
        }
        guard let url = Bundle.module.url(forResource: "email-fingerprints", withExtension: "json") else {
            logger.error("email-fingerprints.json not found in bundle")
            throw FingerprintDatabaseError.resourceNotFound
        }
        let data = try Data(contentsOf: url)
        let wrapper = try JSONDecoder().decode(FingerprintFile.self, from: data)
        cached = wrapper.services
        return wrapper.services
    }

    public func fingerprint(named id: String) async throws -> EmailServiceFingerprint? {
        let all = try await allFingerprints()
        return all.first { $0.id == id }
    }
}

enum FingerprintDatabaseError: Error {
    case resourceNotFound
}

private struct FingerprintFile: Codable {
    let services: [EmailServiceFingerprint]
}
