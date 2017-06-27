#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80281);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/03 20:51:50 $");

  script_cve_id("CVE-2014-3764");
  script_bugtraq_id(71773);
  script_osvdb_id(116250);

  script_name(english:"Palo Alto Networks PAN-OS < 5.0.15 / 5.1.x < 5.1.10 / 6.0.x < 6.0.6 XSS");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Palo Alto Networks PAN-OS
prior to 5.0.15 / 5.1.10 / 6.0.6. It is, therefore, affected by a
cross-site scripting vulnerability in the web-based device management
interface due to improper user input sanitization.");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/27");
  script_set_attribute(attribute:"solution", value:"Upgrade to PAN-OS version 5.0.15 / 5.1.10 / 6.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_dependencies("palo_alto_version.nbin");
  script_require_keys("Host/Palo_Alto/Firewall/Version", "Host/Palo_Alto/Firewall/Full_Version");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

if (version =~ "^6\.0($|[^0-9])")
  fix = "6.0.6";
else if (version =~ "^5\.1($|[^0-9])")
  fix = "5.1.10";
else
  fix = "5.0.15";

# Compare version to fix and report as needed.
if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + full_version +
      '\n  Fixed versions    : ' + fix +
      '\n';
    security_warning(extra:report, port:0);
  }
  else security_warning(0);

  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, full_version);
