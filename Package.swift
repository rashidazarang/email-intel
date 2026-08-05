// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "email-intel",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "EmailIntel", targets: ["EmailIntel"]),
        .executable(name: "EmailIntelMCP", targets: ["EmailIntelMCP"]),
        .executable(name: "email-intel-cli", targets: ["EmailIntelCLI"]),
    ],
    targets: [
        .target(
            name: "EmailIntel",
            resources: [.copy("Resources/email-fingerprints.json")]
        ),
        .executableTarget(
            name: "EmailIntelMCP",
            dependencies: ["EmailIntel"]
        ),
        .executableTarget(
            name: "EmailIntelCLI",
            dependencies: ["EmailIntel"]
        ),
        .testTarget(
            name: "EmailIntelTests",
            dependencies: ["EmailIntel"]
        ),
    ]
)
