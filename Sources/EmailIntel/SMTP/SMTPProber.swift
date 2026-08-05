import Foundation
import Network
import os

public actor SMTPProber {
    private let timeout: TimeInterval
    private let logger = Logger(subsystem: "email-intel", category: "smtp")

    public init(timeout: TimeInterval = 15) {
        self.timeout = timeout
    }

    public func probe(host: String, port: Int = 25) async -> SMTPProfile {
        await withTaskGroup(of: SMTPProfile?.self) { group in
            group.addTask { [timeout] in
                try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                return SMTPProfile(banner: nil, ehloExtensions: [], starttlsSupported: false, tlsVersion: nil)
            }
            group.addTask { [weak self] in
                await self?.runProbe(host: host, port: port)
            }
            for await result in group {
                if let result {
                    group.cancelAll()
                    return result
                }
            }
            return SMTPProfile(banner: nil, ehloExtensions: [], starttlsSupported: false, tlsVersion: nil)
        }
    }

    private func runProbe(host: String, port: Int) async -> SMTPProfile {
        guard let nwPort = NWEndpoint.Port(rawValue: UInt16(port)) else {
            return SMTPProfile(banner: nil, ehloExtensions: [], starttlsSupported: false, tlsVersion: nil)
        }
        let connection = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: .tcp)
        let queue = DispatchQueue(label: "smtp-prober.\(host)")

        let ready: Bool = await withCheckedContinuation { cont in
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready: cont.resume(returning: true)
                case .failed, .cancelled: cont.resume(returning: false)
                default: break
                }
            }
            connection.start(queue: queue)
        }
        connection.stateUpdateHandler = nil

        guard ready else {
            connection.cancel()
            return SMTPProfile(banner: nil, ehloExtensions: [], starttlsSupported: false, tlsVersion: nil)
        }

        let greeting = await receive(connection)
        let banner = SMTPResponse.extractBanner(greeting ?? "")

        await send(connection, "EHLO email-intel\r\n")
        let ehloRaw = await receive(connection) ?? ""
        let extensions = SMTPResponse.parseEHLO(ehloRaw)
        let starttls = extensions.contains { $0.uppercased().contains("STARTTLS") }

        await send(connection, "QUIT\r\n")
        connection.cancel()

        return SMTPProfile(banner: banner, ehloExtensions: extensions, starttlsSupported: starttls, tlsVersion: nil)
    }

    private func send(_ connection: NWConnection, _ text: String) async {
        await withCheckedContinuation { cont in
            connection.send(content: Data(text.utf8), completion: .contentProcessed { _ in
                cont.resume()
            })
        }
    }

    private func receive(_ connection: NWConnection) async -> String? {
        await withCheckedContinuation { cont in
            connection.receive(minimumIncompleteLength: 1, maximumLength: 8192) { data, _, _, _ in
                if let data, !data.isEmpty {
                    cont.resume(returning: String(data: data, encoding: .utf8))
                } else {
                    cont.resume(returning: nil)
                }
            }
        }
    }
}
