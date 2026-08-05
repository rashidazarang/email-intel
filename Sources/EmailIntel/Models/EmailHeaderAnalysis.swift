import Foundation

public struct ReceivedHop: Codable, Sendable {
    public let from: String?
    public let by: String?
    public let tlsUsed: Bool
    public let timestamp: Date?

    public init(from: String?, by: String?, tlsUsed: Bool, timestamp: Date?) {
        self.from = from
        self.by = by
        self.tlsUsed = tlsUsed
        self.timestamp = timestamp
    }
}

public struct AuthenticationMethodResult: Codable, Sendable {
    public let method: String
    public let result: String
    public let detail: String?
    public let reason: String?

    public init(method: String, result: String, detail: String?, reason: String?) {
        self.method = method
        self.result = result
        self.detail = detail
        self.reason = reason
    }
}

public struct AuthenticationResult: Codable, Sendable {
    public let authservId: String
    public let results: [AuthenticationMethodResult]

    public init(authservId: String, results: [AuthenticationMethodResult]) {
        self.authservId = authservId
        self.results = results
    }
}

public struct ARCHeaderSet: Codable, Sendable {
    public let instance: Int
    public let authenticationResults: String
    public let messageSignature: String
    public let seal: String

    public init(instance: Int, authenticationResults: String, messageSignature: String, seal: String) {
        self.instance = instance
        self.authenticationResults = authenticationResults
        self.messageSignature = messageSignature
        self.seal = seal
    }
}

public struct ClientInfo: Codable, Sendable {
    public let mailer: String?
    public let userAgent: String?

    public init(mailer: String?, userAgent: String?) {
        self.mailer = mailer
        self.userAgent = userAgent
    }
}

public struct EmailHeaderAnalysis: Codable, Sendable {
    public let receivedChain: [ReceivedHop]
    public let authenticationResults: [AuthenticationResult]
    public let arcSets: [ARCHeaderSet]
    public let clientInfo: ClientInfo?
    public let listHeaders: [String: String]
    public let returnPath: String?
    public let originatingIP: String?
    public let estimatedDeliverySeconds: Double?

    public init(
        receivedChain: [ReceivedHop],
        authenticationResults: [AuthenticationResult],
        arcSets: [ARCHeaderSet],
        clientInfo: ClientInfo?,
        listHeaders: [String: String],
        returnPath: String?,
        originatingIP: String?,
        estimatedDeliverySeconds: Double?
    ) {
        self.receivedChain = receivedChain
        self.authenticationResults = authenticationResults
        self.arcSets = arcSets
        self.clientInfo = clientInfo
        self.listHeaders = listHeaders
        self.returnPath = returnPath
        self.originatingIP = originatingIP
        self.estimatedDeliverySeconds = estimatedDeliverySeconds
    }
}
