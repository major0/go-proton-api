package domains

// DomainState describes the overall lifecycle state of a custom domain.
type DomainState int

const (
	// DomainStateUnverified indicates the domain has been added but ownership
	// has not yet been verified.
	DomainStateUnverified DomainState = 0
	// DomainStateActive indicates the domain is verified and active.
	DomainStateActive DomainState = 1
	// DomainStateWarning indicates the domain is configured but has a
	// configuration issue requiring attention.
	DomainStateWarning DomainState = 2
)

// VerifyState describes the ownership-verification state of a custom domain.
type VerifyState int

const (
	// VerifyStatePending indicates the ownership TXT record has not yet been
	// detected.
	VerifyStatePending VerifyState = 0
	// VerifyStateGood indicates the ownership TXT record was found and the
	// domain is verified.
	VerifyStateGood VerifyState = 1
	// VerifyStateWarning indicates a verification problem was detected (for
	// example the record was present and then removed).
	VerifyStateWarning VerifyState = 2
)

// DNSRecordStatus describes whether a required DNS record is present and
// correct for a custom domain.
type DNSRecordStatus int

const (
	// DNSRecordStatusNotConfigured indicates the record has not been detected.
	DNSRecordStatusNotConfigured DNSRecordStatus = 0
	// DNSRecordStatusValid indicates the record is present and correct.
	DNSRecordStatusValid DNSRecordStatus = 1
	// DNSRecordStatusInvalid indicates the record is present but incorrect.
	DNSRecordStatusInvalid DNSRecordStatus = 2
)

// Domain is a custom domain registered with an organization. All fields are
// server-side organizational metadata; domains data is not end-to-end
// encrypted.
type Domain struct {
	// ID is the upstream domain identifier.
	ID string
	// Name is the fully qualified domain name (for example "example.com").
	Name string
	// State is the overall lifecycle state of the domain.
	State DomainState
	// VerifyState is the ownership-verification state of the domain.
	VerifyState VerifyState
	// MXState is the configuration status of the domain's MX records.
	MXState DNSRecordStatus
	// SPFState is the configuration status of the domain's SPF record.
	SPFState DNSRecordStatus
	// DKIMState is the configuration status of the domain's DKIM records.
	DKIMState DNSRecordStatus
	// DMARCState is the configuration status of the domain's DMARC record.
	DMARCState DNSRecordStatus
	// CatchAll is the address ID configured as the catch-all for the domain,
	// empty if none is set.
	CatchAll string
	// DNSRecords are the DNS records associated with the domain, when the API
	// includes them in the response.
	DNSRecords []DNSRecord
}

// DNSRecord is a single DNS record the organization must configure for a
// custom domain (verification TXT, MX, SPF, DKIM, DMARC, etc.).
type DNSRecord struct {
	// Type is the DNS record type (for example "TXT", "MX", "CNAME").
	Type string
	// Hostname is the record hostname or subdomain.
	Hostname string
	// Value is the expected record value.
	Value string
	// Status indicates whether the record is present and correct.
	Status DNSRecordStatus
}
