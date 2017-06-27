#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89687);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/07/11 13:15:59 $");

  script_osvdb_id(135053, 135055);

  script_name(english:"Palo Alto Networks PAN-OS Multiple Vulnerabilities (PAN-SA-2016-0002, PAN-SA-2016-0004)");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Palo Alto Networks PAN-OS running on the remote host is version
5.0.x prior to 5.0.18, 5.1.x prior to 5.1.11, 6.0.x prior to 6.0.13,
6.1.x prior to 6.1.10, or 7.0.x prior to 7.0.5-h2. It is, therefore,
affected by the following vulnerabilities :

- An unspecified flaw exists in the GlobalProtect web portal
  due to improper validation of user-supplied input when
  handling requests. An unauthenticated, remote attacker can
  exploit this, via a crafted request, to cause a denial of
  service. (VulnDB 135053)

- A flaw exists in the command line interface (CLI) when
  parsing certain SSH command parameters. An authenticated,
  remote attacker who has administrative privileges can
  exploit this, via a crafted request, to execute arbitrary
  OS commands with root privileges. (VulnDB 135055)");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/35");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/37");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS version 5.0.18 / 5.1.11 / 
6.0.13 / 6.1.10 / 7.0.5-h2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/04");

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
fix = '';
disp_fix = '';
vuln = FALSE;

# Ensure sufficient granularity.
if (
  version =~ "^5(\.0)?$" ||
  version =~ "^5(\.1)?$" ||
  version =~ "^6(\.0)?$" ||
  version =~ "^6(\.1)?$" ||
  version =~ "^7(\.0)?$"
) audit(AUDIT_VER_NOT_GRANULAR, app_name, full_version);

if (version =~ "^7\.0\.")
{
  fix = "7.0.5";
  disp_fix = "7.0.5-h2";
}
else if (version =~ "^6\.1\.")
{
  fix = "6.1.10";
}
else if (version =~ "^6\.0\.")
{
  fix = "6.0.13";
}
else if (version =~ "^5\.1\.")
{
  fix = "5.1.11";
}
else if (version =~ "^5\.0\.")
{
  fix = "5.0.18";
}
else
  audit(AUDIT_INST_VER_NOT_VULN, app_name, full_version);

if(version == "7.0.5")
{
  hotfix = get_kb_item("Host/Palo_Alto/Firewall/Hotfix");
  if(!isnull(hotfix) && (ver_compare(ver:hotfix, fix:'2', strict:FALSE) < 0))
    vuln = TRUE;
}
else
{
  if(ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
    vuln = TRUE;
}

# Compare version to fix and report as needed.
if (vuln)
{
  report =
    '\n  Installed version : ' + full_version;
  if(!empty_or_null(disp_fix))
  {
    report += '\n  Fixed version     : ' + disp_fix +
              '\n';
  }
  else
  {
    report += '\n  Fixed version     : ' + fix +
              '\n';
  }
  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, full_version);
