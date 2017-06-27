#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90797);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/03 14:12:15 $");

  script_cve_id("CVE-2016-2346");
  script_bugtraq_id(87615);
  script_osvdb_id(137574);
  script_xref(name:"CERT", value:"229047");
  script_xref(name:"IAVA", value:"2016-A-0112");

  script_name(english:"Allround Automations PL/SQL Developer < 11.0.6.1776 HTTP Insecure Update RCE");
  script_summary(english:"Checks the version of PL/SQL Developer.");

  script_set_attribute(attribute:'synopsis', value:
"The application installed on the remote host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:'description', value:
"The version of Allround Automations PL/SQL Developer installed on the
remote host is prior to 11.0.6.1776. It is, therefore, affected by a
remote code execution vulnerability due to a failure to properly
verify the origin or authenticity of update data sent via HTTP. A
man-in-the-middle attacker can exploit this to modify the
client-server data stream to change the update, allowing the execution
of arbitrary code.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PL/SQL Developer version 11.0.6.1776 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:allroundautomation:pl%2fsql_developer");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Windows");

  script_dependencies("allauto_plsql_developer.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/PL_SQL Developer");
  script_require_ports(139, 445);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = "PL_SQL Developer";

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
ver      = install['version'];
path     = install['path'];

port = get_kb_item('SMB/transport');
if (!port) port = 445;

# Version 11.0.6 is version 11.0.6.1776
if ( ver_compare(ver:ver, fix:'11.0.6.1776', strict:FALSE) < 0 )
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 11.0.6.1776' +
    '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);
