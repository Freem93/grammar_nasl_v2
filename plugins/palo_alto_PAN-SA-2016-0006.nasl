#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90775);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/03 20:51:50 $");

  script_osvdb_id(137371);

  script_name(english:"Palo Alto Networks PAN-OS HTTP Header Handling URL Filter Bypass (PAN-SA-2016-0006)");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Palo Alto Networks PAN-OS running on the remote host is version
5.0.x, 6.0.x, 6.1.x, 7.0.x, or 7.1.x prior to 7.1.1. It is, therefore,
affected by a security bypass vulnerability in the URL filtering
mechanism, which is triggered when handling a specially crafted HTTP
header. An attacker can exploit this, via a specially crafted header,
to evade URL filtering, potentially allowing a violation of the
intended firewall rule base.");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/39");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS version 7.1.1 or later, which
includes additional inspection for HTTP application identification and
URL categorization. Enforcement of this verification is enabled using
new threat signatures #14984 for HTTP and #14978 for TLS. Note that
PAN-OS must be upgraded to 7.1.1 in order for these new threat
signatures to be enabled.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("palo_alto_version.nbin");
  script_require_keys("Host/Palo_Alto/Firewall/Version", "Host/Palo_Alto/Firewall/Full_Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Palo Alto Networks PAN-OS";
version = get_kb_item_or_exit("Host/Palo_Alto/Firewall/Version");
full_version = get_kb_item_or_exit("Host/Palo_Alto/Firewall/Full_Version");
fix = "7.1.1";

# Ensure sufficient granularity ( only necessary on 7.1.x )
if (version =~ "^7(\.1)?$") audit(AUDIT_VER_NOT_GRANULAR, app_name, full_version);


# Affects 5.0.X, 6.0.X, 6.1.X, 7.0.X 7.1.X < 7.1.1
# Compare version to fix and report as needed.
if 
(
  version =~ '^5\\.0($|\\.)|^6\\.[0-1]($|\\.)|^7\\.0($|\\.)|^7\\.1\\.0' 
  && ver_compare(ver:version, fix:fix, strict:FALSE) < 0
)
{
  report =
    '\n  Installed version : ' + full_version +
    '\n  Fixed version     : ' + fix +
    '\n';

  security_report_v4(port:0, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, full_version);
