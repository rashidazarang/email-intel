import Testing
@testable import EmailIntel

@Test func versionExists() {
    #expect(!EmailIntel.version.isEmpty)
}
