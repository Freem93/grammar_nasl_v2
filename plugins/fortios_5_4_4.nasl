#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97387);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/02/28 14:42:19 $");

  script_osvdb_id(152266, 152267);

  script_name(english:"Fortinet FortiOS 5.4.1 < 5.4.4 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of FortiOS.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Fortinet FortiOS that is 5.4.1
or later but prior to 5.4.4. It is, therefore, affected by the
following vulnerabilities :

  - A security bypass vulnerability exists in the HTTP
    evader tool due to improper handling of HTTP
    content-encoding. An unauthenticated, remote attacker
    can exploit this to bypass antivirus checks.
    (VulnDB 152266)

  - A security bypass vulnerability exists in the DLP
    component that allows an unauthenticated, remote
    attacker to bypass the built-in file-type filter. Note
    that this vulnerability only affects FortiOS version
    5.4.3. (VulnDB 152267)");
  # http://docs.fortinet.com/uploaded/files/3527/fortios-v5.4.4-release-notes.pdf
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?6e87ee62");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiOS 5.4.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version", "Host/Fortigate/build");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "FortiOS";
model    = get_kb_item_or_exit("Host/Fortigate/model");
version  = get_kb_item_or_exit("Host/Fortigate/version");
build    = get_kb_item_or_exit("Host/Fortigate/build");
vuln     = FALSE;
fix = "5.4.4";
fix_build = 1117;

# Make sure device is FortiGate
if (!preg(string:model, pattern:"fortigate", icase:TRUE)) audit(AUDIT_OS_NOT, app_name);

if(version =~ "^5(\.4)?$") audit(AUDIT_VER_NOT_GRANULAR, app_name, version);
else if (version =~ "^5\.4\.[1-3]") vuln = TRUE;
else if (version =~ "^5\.4\.4" && build !~ "Unknown")
{
  if (int(build) < fix_build) vuln = TRUE;
  report_build = build;
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

if (vuln)
{
  report =
    '\n  Model             : ' + model +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix;
  if (!empty_or_null(report_build))
    report +=
      '\n  Installed build   : ' + report_build +
      '\n  Fixed build       : ' + fix_build;

  report += '\n';
  security_report_v4(severity:SECURITY_WARNING, extra:report, port:0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
