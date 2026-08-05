import EmailIntel
import Foundation
import os

actor MCPServer {

    private let transport: JSONRPCTransport
    private static let logger = Logger(subsystem: "com.rashidazarang.emailintel", category: "MCPServer")

    init() {
        self.transport = JSONRPCTransport()
    }

    nonisolated func run() async {
        while let request = transport.readRequest() {
            let id = request["id"]

            guard let method = request["method"] as? String else {
                if id != nil {
                    transport.writeResponse(
                        id: id,
                        result: nil,
                        error: ["code": -32600, "message": "Invalid Request: missing method"]
                    )
                }
                continue
            }

            // JSON-RPC notifications have no id — must not respond
            if id == nil { continue }

            let params = request["params"] as? [String: Any] ?? [:]

            switch method {
            case "initialize":
                transport.writeResponse(id: id, result: Self.initializeResult(), error: nil)

            case "tools/list":
                transport.writeResponse(id: id, result: Self.toolsListResult(), error: nil)

            case "tools/call":
                await dispatchToolCall(id: id, params: params)

            default:
                transport.writeResponse(
                    id: id,
                    result: nil,
                    error: ["code": -32601, "message": "Method not found: \(method)"]
                )
            }
        }
    }

    // MARK: - initialize

    private static func initializeResult() -> [String: Any] {
        [
            "protocolVersion": "2024-11-05",
            "capabilities": ["tools": [String: Any]()] as [String: Any],
            "serverInfo": ["name": "email-intel-mcp", "version": EmailIntel.version] as [String: Any]
        ]
    }

    // MARK: - tools/list

    private static func toolsListResult() -> [String: Any] {
        let tools: [[String: Any]] = [
            [
                "name": "email_intel",
                "description": "Full email intelligence assembly for a domain",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "domain": ["type": "string"] as [String: Any]
                    ] as [String: Any],
                    "required": ["domain"]
                ] as [String: Any]
            ] as [String: Any],
            [
                "name": "dns_lookup",
                "description": "Resolve email-related DNS records (MX/SPF/DMARC/DKIM/TXT)",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "domain": ["type": "string"] as [String: Any]
                    ] as [String: Any],
                    "required": ["domain"]
                ] as [String: Any]
            ] as [String: Any],
            [
                "name": "smtp_probe",
                "description": "Probe an SMTP server for banner, EHLO, STARTTLS support",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "host": ["type": "string"] as [String: Any],
                        "port": ["type": "integer", "default": 25] as [String: Any]
                    ] as [String: Any],
                    "required": ["host"]
                ] as [String: Any]
            ] as [String: Any],
            [
                "name": "email_headers",
                "description": "Parse raw email headers (RFC 5322) into structured analysis",
                "inputSchema": [
                    "type": "object",
                    "properties": [
                        "raw_headers": ["type": "string"] as [String: Any]
                    ] as [String: Any],
                    "required": ["raw_headers"]
                ] as [String: Any]
            ] as [String: Any],
        ]
        return ["tools": tools]
    }

    // MARK: - tools/call

    private nonisolated func dispatchToolCall(id: Any?, params: [String: Any]) async {
        guard let toolName = params["name"] as? String else {
            transport.writeResponse(
                id: id,
                result: nil,
                error: ["code": -32602, "message": "Missing tool name"]
            )
            return
        }

        let args = params["arguments"] as? [String: Any] ?? [:]

        do {
            let result: Any
            switch toolName {
            case "email_intel":
                result = try await Tools.emailIntel(args)
            case "dns_lookup":
                result = try await Tools.dnsLookup(args)
            case "smtp_probe":
                result = try await Tools.smtpProbe(args)
            case "email_headers":
                result = try await Tools.emailHeaders(args)
            default:
                transport.writeResponse(
                    id: id,
                    result: nil,
                    error: ["code": -32602, "message": "Unknown tool: \(toolName)"]
                )
                return
            }

            let text: String
            if let data = try? JSONSerialization.data(
                withJSONObject: result,
                options: [.sortedKeys, .prettyPrinted]
            ), let str = String(data: data, encoding: .utf8) {
                text = str
            } else {
                text = String(describing: result)
            }

            let content: [[String: Any]] = [["type": "text", "text": text]]
            transport.writeResponse(
                id: id,
                result: ["content": content] as [String: Any],
                error: nil
            )
        } catch let error as ToolError {
            transport.writeResponse(
                id: id,
                result: nil,
                error: ["code": -32602, "message": "\(error)"]
            )
        } catch {
            transport.writeResponse(
                id: id,
                result: nil,
                error: ["code": -32603, "message": error.localizedDescription]
            )
        }
    }
}
