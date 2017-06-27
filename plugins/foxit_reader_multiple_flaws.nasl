#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35807);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/08 20:31:54 $");

  script_cve_id("CVE-2009-0191", "CVE-2009-0836", "CVE-2009-0837");
  script_bugtraq_id(34035);
  script_osvdb_id(55614, 55615, 55616);
  script_xref(name:"EDB-ID", value:"8201");
  script_xref(name:"EDB-ID", value:"18905");
  script_xref(name:"Secunia", value:"34036");

  script_name(english:"Foxit Reader 2.x < 2.3 Build 3902 / 3.x < 3.0 Build 1506 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Foxit Reader.");
 
  script_set_attribute(attribute:"synopsis", value:
"A PDF viewer installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Foxit Reader installed on the remote Windows host is
2.x prior to 2.3 Build 3902 or 3.x prior to 3.0 Build 1506. It is,
therefore, affected by multiple vulnerabilities :

  - An uninitialized memory dereference flaw exists due to
    improper handling of a JBIG2 symbol dictionary segment
    with zero new symbols. An unauthenticated, remote
    attacker can exploit this, via a crafted PDF file, to
    execute arbitrary code. (CVE-2009-0191)

  - A flaw exists due to a failure to require user
    authorization before preforming dangerous actions
    defined in a PDF file. An unauthenticated, remote
    attacker can exploit this, via a crafted PDF file, to
    execute arbitrary commands. (CVE-2009-0836)

  - A stack-based buffer overflow condition exists due to
    improper sanitization of user-supplied input. An
    unauthenticated, remote attacker can exploit this to
    execute arbitrary code via a crafted PDF file having a
    long relative or absolute path in a filename argument in
    an action. Note that this issue only affects version
    3.x. (CVE-2009-0837)");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2009-11/");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/company/press.php?id=97");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit Reader version 2.3 Build 3902 / 3.0 Build 1506 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Foxit Reader 3.0 Open Execute Action Stack Based Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94, 119);

  script_set_attribute(attribute:"vuln_publication_date", value: "2009/03/09");
  script_set_attribute(attribute:"patch_publication_date", value: "2009/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value: "2009/03/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:foxitsoftware:foxit_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("foxit_reader_installed.nasl");
  script_require_keys("installed_sw/Foxit Reader");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = "Foxit Reader";
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
version = install["version"];
path    = install["path"];

report = NULL;
fixed_version = NULL;

if (version =~ "^2\.3\.")
  fixed_version = "2.3.3902";

if (version =~ "^3\.0\.")
  fixed_version = "3.0.1506";

# Remove the year from the version where applicable
ver_ui = NULL;
if (ereg(pattern:"200[789]\.", string:version))
{
  ver_ui = version;
  version = ereg_replace(pattern:"(200[789]\.)", replace:"", string:version);
}

if (fixed_version && ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port)
    port = 445;

  report = '\n  Path              : ' + path;

  if (!isnull(ver_ui))
    report += '\n  UI version        : ' + ver_ui;

  report +=
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed_version + '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
