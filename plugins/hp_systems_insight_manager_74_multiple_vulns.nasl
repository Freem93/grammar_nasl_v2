#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78079);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/21 22:04:46 $");

  script_cve_id("CVE-2014-2643", "CVE-2014-2644", "CVE-2014-2645");
  script_bugtraq_id(70223, 70224, 70225);
  script_osvdb_id(112679, 112680, 112681);
  script_xref(name:"HP", value:"emr_na-c04468121");
  script_xref(name:"HP", value:"HPSBMU03118");
  script_xref(name:"HP", value:"SSRT101715");

  script_name(english:"HP Systems Insight Manager < 7.4 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of HP Systems Insight Manager.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains software that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of HP Systems Insight Manager installed on the remote
Windows host is affected by the following vulnerabilities :

  - An unspecified vulnerability exists that allows a remote
    authenticated attacker to gain limited elevated
    privileges. (CVE-2014-2643)

  - A vulnerability exists that allows reflected cross-site
    scripting attacks, due to the improper validation of
    user-supplied input before it is returned to the users.
    Using a specially crafted request, a remote attacker can
    execute arbitrary script code within a user's browser.
    (CVE-2014-2644)

  - An unspecified flaw exists that allows a remote attacker
    to conduct a clickjacking attack. (CVE-2014-2645)");
  # https://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04468121
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?81ea99e8");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/533606/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/533635/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP Systems Insight Manager 7.4 or later. A hotfix has also
been made available for HP Systems Insight Manager 7.2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:systems_insight_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_systems_insight_manager_installed.nasl");
  script_require_keys("installed_sw/HP Systems Insight Manager");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");

app_name = "HP Systems Insight Manager";
report   = NULL;

install = get_single_install(app_name:app_name);
path    = install['path'];
version = install['version'];

# A hotfix is available for 7.2
if (version =~ '^(([A-C]\\.)?07\\.02\\.[0-9\\.]+)')
{
  hotfixes = install['Hotfixes'];
  if (empty_or_null(hotfixes)) hotfixes = 'None';
  else hotfixes = str_replace(string:hotfixes, find:";", replace:", ");

  fixed_hotfix = 'HOTFIX72_038';
  if (fixed_hotfix >!< hotfixes)
    report =
      '\n  Path               : ' + path +
      '\n  Installed version  : ' + version +
      '\n  Installed hotfixes : ' + hotfixes +
      '\n  Fixed hotfix       : ' + fixed_hotfix + '\n';
}
else if (version =~ '^(([A-Z]\\.)?0[0-6]\\.|([A-C]\\.)?07\\.0[0-3]\\.[0-9\\.]+)')
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : C.07.04.00.00\n';
}

if (!isnull(report))
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0) security_warning(port:port, extra:report);
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
