import Foundation

actor JSONRPCTransport {

    init() {}

    /// Reads one line from stdin and parses it as a JSON-RPC request.
    nonisolated func readRequest() -> [String: Any]? {
        guard let line = readLine(strippingNewline: true),
              !line.isEmpty,
              let data = line.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        return json
    }

    /// Writes a JSON-RPC 2.0 response as a single line to stdout.
    nonisolated func writeResponse(id: Any?, result: Any?, error: [String: Any]?) {
        var response: [String: Any] = ["jsonrpc": "2.0"]
        response["id"] = id ?? NSNull()
        if let error {
            response["error"] = error
        } else if let result {
            response["result"] = result
        } else {
            response["result"] = NSNull()
        }
        guard let data = try? JSONSerialization.data(withJSONObject: response),
              var line = String(data: data, encoding: .utf8) else { return }
        line.append("\n")
        if let outputData = line.data(using: .utf8) {
            FileHandle.standardOutput.write(outputData)
        }
    }
}
