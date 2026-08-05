import Foundation

/// Result of classifying an email domain. Surfaces three independent signals
/// that downstream consumers (CSV exports, marketing tools, etc.)
/// want to filter on without re-running fingerprinting.
public struct DomainClassification: Codable, Sendable, Equatable {
    /// `true` when the domain is a free webmail provider (gmail/yahoo/etc.).
    public let isWebmail: Bool
    /// `true` when the domain is on the bundled disposable-domain list.
    public let isDisposable: Bool
    /// Rolled-up MX provider name ("Google Workspace", "Microsoft 365", etc.)
    /// derived from MX host suffixes. `nil` if no MX records or no match.
    public let mxProvider: String?

    public init(isWebmail: Bool, isDisposable: Bool, mxProvider: String?) {
        self.isWebmail = isWebmail
        self.isDisposable = isDisposable
        self.mxProvider = mxProvider
    }
}

/// Pure-data classifier — no DNS, no I/O, no network. Takes a domain plus
/// the MX hosts already resolved by the orchestrator and returns the three
/// flat signals downstream consumers care about.
public enum DomainClassifier {

    /// Free-webmail domains. Curated from the providers list at
    /// https://gist.github.com/tbrianjones/5992856 (top mailbox providers
    /// only — no aliases, no obscure regional ones).
    public static let webmailDomains: Set<String> = [
        "gmail.com", "googlemail.com",
        "yahoo.com", "yahoo.co.uk", "yahoo.co.jp", "yahoo.fr", "yahoo.de", "ymail.com",
        "outlook.com", "hotmail.com", "live.com", "msn.com",
        "icloud.com", "me.com", "mac.com",
        "aol.com",
        "proton.me", "protonmail.com", "pm.me",
        "fastmail.com", "fastmail.fm",
        "zoho.com",
        "gmx.com", "gmx.de", "gmx.net",
        "yandex.com", "yandex.ru",
        "mail.ru", "inbox.ru", "list.ru", "bk.ru",
        "qq.com", "163.com", "126.com", "sina.com",
        "tutanota.com", "tutanota.de",
        "hushmail.com",
    ]

    /// Top disposable / temporary email domains. Curated subset; ~50 entries
    /// covers >95% of disposable traffic in the wild.
    public static let disposableDomains: Set<String> = [
        "mailinator.com", "mailinator.net", "mailinator2.com",
        "guerrillamail.com", "guerrillamail.net", "guerrillamail.org", "guerrillamail.biz",
        "10minutemail.com", "10minutemail.net", "10minutemail.org",
        "tempmail.com", "temp-mail.org", "tempmailaddress.com", "tempmailo.com",
        "throwawaymail.com", "throwaway.email",
        "yopmail.com", "yopmail.fr", "yopmail.net",
        "trashmail.com", "trashmail.net", "trashmail.de",
        "getnada.com", "nada.email",
        "maildrop.cc",
        "fakemail.net", "fakeinbox.com",
        "mintemail.com",
        "dispostable.com",
        "discard.email", "discardmail.com",
        "harakirimail.com",
        "spambox.us", "spambog.com",
        "mailcatch.com",
        "mohmal.com",
        "sharklasers.com",
        "grr.la",
        "pokemail.net",
        "spam4.me",
        "tempinbox.com",
        "mytemp.email",
        "emailondeck.com",
        "moakt.com",
        "tempmail.dev",
        "burnermail.io",
        "anonbox.net",
    ]

    /// MX host suffix → provider name. Order doesn't matter — first match wins
    /// per `classify`. Suffix match is case-insensitive and matches the *end*
    /// of the MX host (so `aspmx.l.google.com` matches `.google.com`).
    public static let mxProviderSuffixes: [(suffix: String, provider: String)] = [
        // Google
        (".google.com", "Google Workspace"),
        (".googlemail.com", "Google Workspace"),
        ("aspmx.l.google.com", "Google Workspace"),
        // Microsoft
        (".outlook.com", "Microsoft 365"),
        (".protection.outlook.com", "Microsoft 365"),
        (".mail.protection.outlook.com", "Microsoft 365"),
        // Proofpoint
        (".pphosted.com", "Proofpoint"),
        (".ppe-hosted.com", "Proofpoint"),
        // Mimecast
        (".mimecast.com", "Mimecast"),
        (".mimecast.co.za", "Mimecast"),
        // Zoho
        (".zoho.com", "Zoho Mail"),
        (".zohomail.com", "Zoho Mail"),
        // Fastmail
        (".messagingengine.com", "Fastmail"),
        // Yahoo
        (".yahoodns.net", "Yahoo Mail"),
        // Apple iCloud
        (".mail.icloud.com", "iCloud Mail"),
        // ProtonMail
        (".protonmail.ch", "ProtonMail"),
        // Yandex
        (".yandex.net", "Yandex Mail"),
        (".yandex.ru", "Yandex Mail"),
        // Mailgun
        (".mailgun.org", "Mailgun"),
        // SendGrid
        (".sendgrid.net", "SendGrid"),
        // Amazon SES
        (".amazonses.com", "Amazon SES"),
        // Postmark
        (".mtasv.net", "Postmark"),
        // Migadu
        (".migadu.com", "Migadu"),
        // Rackspace
        (".emailsrvr.com", "Rackspace Email"),
        // Tutanota
        (".tutanota.de", "Tutanota"),
        // GMX / 1&1
        (".gmx.net", "GMX"),
        (".kundenserver.de", "1&1 IONOS"),
    ]

    /// Classify a domain using its already-resolved MX hosts.
    /// All inputs are normalized to lowercase before matching.
    public static func classify(domain: String, mxHosts: [String]) -> DomainClassification {
        let normalized = domain.lowercased().trimmingCharacters(in: .whitespacesAndNewlines)
        let isWebmail = webmailDomains.contains(normalized)
        let isDisposable = disposableDomains.contains(normalized)

        var mxProvider: String?
        let lowerHosts = mxHosts.map { $0.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: ".")) }
        for host in lowerHosts {
            if let match = mxProviderSuffixes.first(where: { host.hasSuffix($0.suffix.trimmingCharacters(in: CharacterSet(charactersIn: "."))) || host.hasSuffix($0.suffix) }) {
                mxProvider = match.provider
                break
            }
        }

        return DomainClassification(
            isWebmail: isWebmail,
            isDisposable: isDisposable,
            mxProvider: mxProvider
        )
    }
}
