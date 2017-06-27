#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 6000) exit(0, "Nessus older than 6.0.x");

include("compat.inc");

if (description)
{
  script_id(93125);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/23 20:42:23 $");

  script_cve_id("CVE-2016-1712");
  script_osvdb_id(141162);

  script_name(english:"Palo Alto Networks PAN-OS 5.0.x < 5.0.19 / 5.1.x < 5.1.12 / 6.0.x < 6.0.14 / 6.1.x < 6.1.12 / 7.0.x < 7.0.8 Privilege Escalation (PAN-SA-2016-0012)");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The version of Palo Alto Networks PAN-OS running on the remote host is
5.0.x prior to 5.0.19, 5.1.x prior to 5.1.12, 6.0.x prior to 6.0.14,
6.1.x prior to 6.1.12, or 7.0.x prior to 7.0.8. It is, therefore,
affected by a privilege escalation vulnerability due to improper
sanitization of the root_reboot local invocation. A local attacker can
exploit this to gain elevated privileges.");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/45");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS version 5.0.19 / 5.1.12 / 6.0.14
/ 6.1.12 / 7.0.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/26");

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
fix = NULL;

# Ensure sufficient granularity.
if (version !~ "^\d+\.\d+") audit(AUDIT_VER_NOT_GRANULAR, app_name, full_version);

switch[=~] (version)
{
  case "^5\.0\.([0-9]|1[0-8])($|[^0-9])":
    fix = "5.0.19";
    break;
  case "^5\.1\.([0-9]|1[0-1])($|[^0-9])":
    fix = "5.1.12";
    break;
  case "^6\.0\.([0-9]|1[0-3])($|[^0-9])":
    fix = "6.0.14";
    break;
  case "^6\.1\.([0-9]|1[0-1])($|[^0-9])":
    fix = "6.1.12";
    break;
  case "^7\.0\.[0-7]($|[^0-9])":
    fix = "7.0.8";
    break;
  default:
    audit(AUDIT_INST_VER_NOT_VULN, app_name, full_version);
}

report =
  '\n  Installed version : ' + full_version +
  '\n  Fixed version     : ' + fix +
  '\n';
security_report_v4(severity:SECURITY_HOLE, extra:report, port:0);
