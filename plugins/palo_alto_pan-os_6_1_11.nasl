#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91969);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/07/08 14:36:37 $");

  script_osvdb_id(139991, 139995);

  script_name(english:"Palo Alto Networks PAN-OS 6.1.x < 6.1.11 Multiple Vulnerabilities");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The version of Palo Alto Networks PAN-OS running on the remote host is
6.1.x < 6.1.11. It is, therefore, affected by multiple vulnerabilities :

  - An unspecified flaw exists that allows an authenticated,
    remote attacker to access potentially sensitive
    information in the system logs. (VulnDB 139991)

  - A security bypass vulnerability exists in the XML API
    that allows an authenticated, remote attacker with
    superuser read-only permissions to bypass intended
    restrictions and perform a commit. (VulnDB 139995)");
  # https://www.paloaltonetworks.com/documentation/61/pan-os/pan-os-release-notes/pan-os-6-1-11-addressed-issues#85202
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?acc11a81");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS version 6.1.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/07");

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
fix = '6.1.11';

# Ensure sufficient granularity.
if (version !~ "^\d+\.\d+") audit(AUDIT_VER_NOT_GRANULAR, app_name, full_version);

# 6.1.x is affected.
if (version !~ "^6\.1($|[^0-9])") audit(AUDIT_INST_VER_NOT_VULN, app_name, full_version);

# Compare version to vuln and report as needed.
if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  Installed version : ' + full_version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(severity:SECURITY_WARNING, extra:report, port:0);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, full_version);
