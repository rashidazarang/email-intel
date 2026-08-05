import Foundation
import EmailIntel

// Tiny CLI bridge: `email-intel-cli <domain>` → JSON dossier on stdout.
// Also supports `email-intel-cli headers <path|->` for delivery-header analysis.
// JSON on stdout, human-readable errors on stderr — easy to subprocess from any language
// without reimplementing DNS/SPF/DKIM/DMARC parsing in JS.
//
// Exit codes:
//   0 — JSON dossier emitted on stdout
//   1 — usage error
//   2 — lookup failure (network / parse / classifier error)

@main
struct EmailIntelCLI {
    static func main() async {
        let args = CommandLine.arguments

        if args.contains("--version") || args.contains("-v") {
            print(EmailIntel.version)
            return
        }

        guard args.count >= 2 else {
            printUsage()
            exit(1)
        }

        if args[1] == "headers" {
            analyzeHeaders(args: args)
            return
        }

        let domain = args[1]
        let engine = EmailIntelligenceEngine()

        do {
            let intelligence = try await engine.lookup(domain: domain)
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
            let data = try encoder.encode(intelligence)
            FileHandle.standardOutput.write(data)
            FileHandle.standardOutput.write(Data("\n".utf8))
        } catch {
            let message = "Lookup failed for \(domain): \(error)\n"
            FileHandle.standardError.write(Data(message.utf8))
            exit(2)
        }
    }

    private static func analyzeHeaders(args: [String]) {
        guard args.count >= 3 else {
            printUsage()
            exit(1)
        }

        let rawHeaders: String
        if args[2] == "-" {
            rawHeaders = String(data: FileHandle.standardInput.readDataToEndOfFile(), encoding: .utf8) ?? ""
        } else {
            do {
                rawHeaders = try String(contentsOfFile: args[2], encoding: .utf8)
            } catch {
                FileHandle.standardError.write(Data("Unable to read headers at \(args[2]): \(error)\n".utf8))
                exit(1)
            }
        }

        let analysis = EmailHeaderParser.parse(rawHeaders: rawHeaders)
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
            encoder.dateEncodingStrategy = .iso8601
            let data = try encoder.encode(analysis)
            FileHandle.standardOutput.write(data)
            FileHandle.standardOutput.write(Data("\n".utf8))
        } catch {
            FileHandle.standardError.write(Data("Header analysis failed: \(error)\n".utf8))
            exit(2)
        }
    }

    private static func printUsage() {
        FileHandle.standardError.write(Data("Usage: email-intel-cli <domain>\n".utf8))
        FileHandle.standardError.write(Data("       email-intel-cli headers <path|->\n".utf8))
        FileHandle.standardError.write(Data("       email-intel-cli --version\n".utf8))
    }
}
