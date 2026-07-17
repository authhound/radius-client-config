package clientconfig

import (
	"fmt"
	"strings"
)

// renderFreeRADIUS produces a copy-paste-ready clients.conf block for
// FreeRADIUS 3.x. Output syntax is deliberately conservative: only fields
// documented for currently-shipping 3.x, with version caveats in comments
// where 3.0 and 3.2 differ.
func renderFreeRADIUS(r *resolved) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# FreeRADIUS 3.x client block — %s\n", generatedBy)
	b.WriteString("# Add to clients.conf:\n")
	b.WriteString("#   Debian/Ubuntu: /etc/freeradius/3.0/clients.conf\n")
	b.WriteString("#   RHEL/Rocky:    /etc/raddb/clients.conf\n")
	fmt.Fprintf(&b, "client %s {\n", r.req.Name)
	fmt.Fprintf(&b, "\tipaddr = %s\n", r.addressString())
	fmt.Fprintf(&b, "\tsecret = %s\n", quoteFreeRADIUS(r.secret))
	if r.req.NASType != "" {
		fmt.Fprintf(&b, "\tnas_type = %s\n", r.req.NASType)
	}
	if r.requireMA {
		b.WriteString("\t# Require Message-Authenticator on every request from this client\n")
		b.WriteString("\t# (BlastRADIUS hardening). Requires FreeRADIUS 3.2.5+ / 3.0.27+;\n")
		b.WriteString("\t# remove this line on older versions.\n")
		b.WriteString("\trequire_message_authenticator = yes\n")
	}
	b.WriteString("}\n")
	b.WriteString("# Check syntax, then reload:\n")
	b.WriteString("#   Debian/Ubuntu: freeradius -XC && systemctl reload freeradius\n")
	b.WriteString("#   RHEL/Rocky:    radiusd -XC && systemctl reload radiusd\n")
	writeSharedNotes(&b, r, "# ")
	return b.String()
}

// quoteFreeRADIUS renders the secret as a clients.conf double-quoted string.
// The generated charsets never need escaping; this exists for user-supplied
// secrets (and validate() warns separately when one contains characters,
// like $, that quoting alone cannot make safe at config-parse time).
func quoteFreeRADIUS(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

// writeSharedNotes appends the entropy, NAT, and optional CoA notes with the
// given comment prefix. Both renderers call this so the note set and order
// are identical in the two outputs.
func writeSharedNotes(b *strings.Builder, r *resolved, prefix string) {
	if r.generated {
		b.WriteString(prefix + fmt.Sprintf(entropyNote, len(r.secret), r.charsetSize, r.entropyBits) + "\n")
	}
	for _, line := range strings.Split(NATNote, "\n") {
		b.WriteString(prefix + line + "\n")
	}
	if r.req.CoANote {
		for _, line := range strings.Split(CoANote, "\n") {
			b.WriteString(prefix + line + "\n")
		}
	}
}
