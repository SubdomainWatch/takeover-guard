package correlator

// Severity levels matching specification
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityWarning  = "WARNING"
)

// Rule IDs defined in specification §8
const (
	RuleUncoordinatedOrphan = "SW-G-001"
	RuleDanglingPointer     = "SW-G-002"
	RuleComputedTarget      = "SW-G-003"
)

// Terraform Plan JSON data structures
type PlanJSON struct {
	FormatVersion    string           `json:"format_version,omitempty"`
	TerraformVersion string           `json:"terraform_version,omitempty"`
	ResourceChanges  []ResourceChange `json:"resource_changes"`
}

type ResourceChange struct {
	Address       string    `json:"address"`
	ModuleAddress string    `json:"module_address,omitempty"`
	Mode          string    `json:"mode,omitempty"`
	Type          string    `json:"type"`
	Name          string    `json:"name"`
	ProviderName  string    `json:"provider_name,omitempty"`
	Change        ChangeObj `json:"change"`
}

type ChangeObj struct {
	Actions      []string       `json:"actions"`
	Before       map[string]any `json:"before"`
	After        map[string]any `json:"after"`
	AfterUnknown map[string]any `json:"after_unknown"`
}

// Finding represents a single security issue detected in the plan
type Finding struct {
	RuleID     string `json:"rule_id"`
	Severity   string `json:"severity"`
	FQDN       string `json:"fqdn"`
	Target     string `json:"target"`
	Address    string `json:"address,omitempty"`
	SourceFile string `json:"source_file,omitempty"`
	StartLine  int    `json:"start_line,omitempty"`
	Reason     string `json:"reason"`
}

// ProbeStatus represents the outcome of a live claimability probe
type ProbeStatus string

const (
	ProbeStatusClean         ProbeStatus = "CLEAN"
	ProbeStatusConfirmed     ProbeStatus = "CONFIRMED"
	ProbeStatusIndeterminate ProbeStatus = "INDETERMINATE"
)

// IndeterminateTarget represents a target that could not be verified due to DNS or transport timeouts
type IndeterminateTarget struct {
	FQDN    string `json:"fqdn"`
	Target  string `json:"target"`
	Address string `json:"address,omitempty"`
	Reason  string `json:"reason"`
}

// EvaluationResult contains the full analysis of a Terraform plan
type EvaluationResult struct {
	Findings             []Finding             `json:"findings"`
	IndeterminateTargets []IndeterminateTarget `json:"indeterminate_targets,omitempty"`
	TotalModifiedRecords int                   `json:"total_modified_records"`
}

// ProberInterface abstracts claimability checks for decoupling and unit testing
type ProberInterface interface {
	IsCloudProviderTarget(target string) bool
	ProbeClaimability(fqdn, target string) (isVulnerable bool, severity string, remediation string)
}

// DetailedProber extends ProberInterface to return precise ProbeStatus (clean, confirmed, indeterminate)
type DetailedProber interface {
	ProberInterface
	ProbeClaimabilityDetailed(fqdn, target string) (status ProbeStatus, severity string, remediation string, errReason string)
}

