package clientconfig

import (
	"fmt"
	"strings"
)

// renderNPS produces the Windows NPS PowerShell registration. The cmdlet
// call matches the documented New-NpsRadiusClient signature
// ([-Name] [-Address] [-AuthAttributeRequired] [-SharedSecret] [-VendorName]
// [-Disabled]); anything the cmdlet cannot express is a comment, not a guess.
func renderNPS(r *resolved) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Windows NPS RADIUS client — %s\n", generatedBy)
	b.WriteString("# Run in an ELEVATED PowerShell prompt on the NPS server:\n")
	fmt.Fprintf(&b, "New-NpsRadiusClient -Name %s -Address %s -SharedSecret %s -AuthAttributeRequired $%t\n",
		quotePowerShell(r.req.Name), quotePowerShell(r.addressString()), quotePowerShell(r.secret), r.requireMA)
	b.WriteString("Restart-Service IAS  # NPS only applies new RADIUS clients after a service restart\n")
	if r.requireMA {
		b.WriteString("# -AuthAttributeRequired $true = console option \"Access-Request messages must\n")
		b.WriteString("#   contain the Message-Authenticator attribute\" (BlastRADIUS hardening;\n")
		b.WriteString("#   matches require_message_authenticator on the FreeRADIUS side).\n")
	} else {
		b.WriteString("# -AuthAttributeRequired $false is the NPS default; post-BlastRADIUS guidance\n")
		b.WriteString("#   is to enable it once the client is confirmed to send Message-Authenticator.\n")
	}
	if r.isCIDR {
		b.WriteString("# Address ranges: NPS accepts CIDR ranges on Windows Server 2016 and later,\n")
		b.WriteString("#   but the cmdlet documents -Address as an IP or FQDN only — if the command\n")
		b.WriteString("#   is rejected, enter the range in the console (path below) instead.\n")
	}
	if r.req.NASType != "" {
		b.WriteString("# nas_type is FreeRADIUS-only. The NPS equivalent, -VendorName, defaults to\n")
		b.WriteString("#   'RADIUS Standard', which is correct for most gear — set it only if a\n")
		b.WriteString("#   policy matches on Client-Vendor.\n")
	}
	b.WriteString("# GUI alternative: nps.msc > RADIUS Clients and Servers > RADIUS Clients >\n")
	fmt.Fprintf(&b, "#   New > \"Address (IP or DNS)\": %s\n", r.addressString())
	fmt.Fprintf(&b, "# NPS limits shared secrets to %d characters.\n", NPSMaxSecretLength)
	writeSharedNotes(&b, r, "# ")
	return b.String()
}

// quotePowerShell renders a PowerShell single-quoted string, where the only
// escape is doubling embedded single quotes.
func quotePowerShell(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
