#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70806);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/21 22:04:45 $");

  script_cve_id(
    "CVE-2013-4837",
    "CVE-2013-4838",
    "CVE-2013-4839",
    "CVE-2013-6213"
  );
  script_bugtraq_id(63475, 63476, 63477, 66961);
  script_osvdb_id(99231, 99232, 99233, 106008);
  script_xref(name:"HP", value:"HPSBMU02935");
  script_xref(name:"HP", value:"SSRT101191");
  script_xref(name:"HP", value:"SSRT101192");
  script_xref(name:"HP", value:"SSRT101193");
  script_xref(name:"HP", value:"SSRT101357");
  script_xref(name:"HP", value:"emr_na-c03969437");

  script_name(english:"HP LoadRunner < 11.52 Patch 1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of HP LoadRunner.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of HP LoadRunner installed on the remote host is prior to
11.52 Patch 1. It is, therefore, affected by multiple
vulnerabilities :

  - Flaws exist in the Virtual User Generator that allow
    directory traversal outside of a restricted path. These
    can be exploited by a remote attacker to create files
    with arbitrary content, thus leading to remote code
    execution. (CVE-2013-4837, CVE-2013-4838)

  - A SQL injection vulnerability exists in the Virtual User
    Generator that allows remote attackers to acquire
    sensitive information, modify data, or cause a denial of
    service. (CVE-2013-4839)

  - A flaw exists in the Virtual User Generator when
    handling multiple unspecified methods that allows a
    remote attacker to read, write, or delete arbitrary
    files, thus leading to information disclosure or the
    execution of arbitrary code. (CVE-2013-6213)");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-259/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-260/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-261/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-100/");
  # https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c03969437
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?97598423");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/531867/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP LoadRunner 11.52 Patch 1 or later or apply the
workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HP LoadRunner EmulationAdmin Web Service Directory Traversal');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:loadrunner");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_loadrunner_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/HP LoadRunner");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");

app_name = "HP LoadRunner";

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);

version = install['version'];
path = install['path'];
verui = install['display_version'];

# 11.52.0 fix is 11.52.1517.0
fixed = "11.52.1517.0";
if (ver_compare(ver:version, fix:fixed, strict:FALSE) == -1)
{
  # Check for workaround : ServiceEmulator Tomcat Webapp is removed
  webapp = "\apache-tomcat-5.5.17\webapps\ServiceEmulation\WEB-INF\service-emulation.jar";
  webapp_path = hotfix_append_path(path:path, value:webapp);

  file_exists = hotfix_file_exists(path:webapp_path);
  hotfix_check_fversion_end();

  if (isnull(file_exists))
    exit(1, 'An error occurred while attempting to access ' + webapp_path + '.');
  if (!file_exists)
    audit(AUDIT_INST_PATH_NOT_VULN, app_name, verui, path);

  # Host is vulnerable
  set_kb_item(name:'www/0/SQLInjection', value:TRUE);

  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed + ' (11.52 Patch 1)' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, verui, path);
