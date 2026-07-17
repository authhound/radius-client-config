package clientconfig

// SchemaVersion identifies the JSON document shape produced for --json and
// the WASM API. Major version only: bump it on any backward-incompatible
// change (same convention as authhound-probe).
const SchemaVersion = "1"

// Result carries both rendered outputs for one Request. The secret appears
// in the rendered texts and in Secret; callers own keeping it off the wire
// and out of logs (the CLI and the browser page never transmit it anywhere).
type Result struct {
	SchemaVersion string `json:"schema_version"`
	// FreeRADIUS is the clients.conf block, ready to paste.
	FreeRADIUS string `json:"freeradius"`
	// NPS is the PowerShell registration, ready to paste.
	NPS string `json:"nps"`
	// Secret is the shared secret embedded in both outputs.
	Secret          string `json:"secret"`
	SecretGenerated bool   `json:"secret_generated"`
	// EntropyBits is floor(length * log2(charset size)); 0 for user-supplied
	// secrets, whose entropy this tool cannot know.
	EntropyBits int      `json:"entropy_bits,omitempty"`
	Warnings    []string `json:"warnings,omitempty"`
}

// Generate validates req, resolves or generates the secret, and renders both
// outputs. It is the single entry point used by the CLI and the WASM bridge,
// which is what guarantees the two surfaces produce identical output for
// identical input.
func Generate(req Request) (Result, error) {
	r, err := validate(req)
	if err != nil {
		return Result{}, err
	}
	return Result{
		SchemaVersion:   SchemaVersion,
		FreeRADIUS:      renderFreeRADIUS(r),
		NPS:             renderNPS(r),
		Secret:          r.secret,
		SecretGenerated: r.generated,
		EntropyBits:     r.entropyBits,
		Warnings:        r.warnings,
	}, nil
}
