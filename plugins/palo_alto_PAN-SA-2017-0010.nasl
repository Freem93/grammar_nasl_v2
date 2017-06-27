#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 6000) exit(0, "Nessus older than 6.0.x");

include("compat.inc");

if (description)
{
  script_id(99438);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/04/18 13:47:29 $");

  script_cve_id(
    "CVE-2017-7126",
    "CVE-2017-7217",
    "CVE-2017-7218"
  );
  script_bugtraq_id(
    97590,
    97592,
    97598
  );
  script_osvdb_id(
    155216,
    155217,
    155218
  );

  script_name(english:"Palo Alto Networks PAN-OS 7.0.x < 7.0.14 / 7.1.x < 7.1.9 Multiple Vulnerabilities (PAN-SA-2017-0008 - PAN-SA-2017-0010)");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The version of Palo Alto Networks PAN-OS running on the remote host is
7.0.x prior to 7.0.14 or 7.1.x prior to 7.1.9. It is, therefore,
affected by multiple vulnerabilities :

  - A flaw exists in the Management Web Interface due to
    improper validation of certain request parameters. An
    authenticated, remote attacker can exploit this to
    disclose potentially sensitive information. Note that
    this vulnerability only affects the 7.1.x version.
    (CVE-2017-7126)

  - A flaw exists in the Management Web Interface due to
    improper validation of certain request parameters. An
    authenticated, remote attacker can exploit this to
    write arbitrary data to export files. (CVE-2017-7217)

  - A flaw exists in the Management Web Interface due to
    improper validation of certain request parameters. A
    local attacker can exploit this to execute arbitrary
    code with elevated privileges. Note that this
    vulnerability only affects the 7.1.x version.
    (CVE-2017-7218)");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/78");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/79");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/80");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS version 7.0.14 / 7.1.9 or later.

As a workaround or mitigation, Palo Alto Networks recommends allowing
web interface access only to a dedicated management network.
Additionally, restrict the set of IP addresses to a subset of
authorized sources that you allow to interact with the management
network.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

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
if (version !~ "^\d+\.\d+\.\d+") audit(AUDIT_VER_NOT_GRANULAR, app_name, full_version);

switch[=~] (version)
{
  case "^7\.0\.([0-9]|1[0-3])($|[^0-9])":
    fix = "7.0.14";
    break;
  case "^7\.1\.[0-8]($|[^0-9])":
    fix = "7.1.9";
    break;
  default:
    audit(AUDIT_INST_VER_NOT_VULN, app_name, full_version);
}

report =
  '\n  Installed version : ' + full_version +
  '\n  Fixed version     : ' + fix +
  '\n';
security_report_v4(severity:SECURITY_HOLE, extra:report, port:0);
