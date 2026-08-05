import Foundation

public struct DNSProfile: Codable, Sendable {
    public let mxRecords: [String]
    public let spfRecord: String?
    public let dkimFound: Bool
    public let dmarcRecord: String?
    public let dmarcPolicy: String?
    public let txtRecords: [String]

    public init(
        mxRecords: [String],
        spfRecord: String?,
        dkimFound: Bool,
        dmarcRecord: String?,
        dmarcPolicy: String?,
        txtRecords: [String]
    ) {
        self.mxRecords = mxRecords
        self.spfRecord = spfRecord
        self.dkimFound = dkimFound
        self.dmarcRecord = dmarcRecord
        self.dmarcPolicy = dmarcPolicy
        self.txtRecords = txtRecords
    }
}
