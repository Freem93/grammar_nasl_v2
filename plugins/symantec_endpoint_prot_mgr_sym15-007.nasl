#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85256);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/06/20 20:49:18 $");

  script_cve_id(
    "CVE-2015-1486",
    "CVE-2015-1487",
    "CVE-2015-1488",
    "CVE-2015-1489",
    "CVE-2015-1490",
    "CVE-2015-1491",
    "CVE-2015-1492"
  );
  script_bugtraq_id(
    76074,
    76077,
    76078,
    76079,
    76081,
    76094,
    76083
  );
  script_osvdb_id(
    125662,
    125663,
    125664,
    125665,
    125666,
    125667,
    125668,
    135139,
    135140,
    135141
  );
  script_xref(name:"EDB-ID", value:"37812");

  script_name(english:"Symantec Endpoint Protection Manager 11.x / 12.x < 12.1 RU6 MP1 Multiple Vulnerabilities (SYM15-007)");
  script_summary(english:"Checks the SEPM version.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Symantec Endpoint Protection Manager installed on the
remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Endpoint Protection Manager (SEPM) installed
on the remote host is prior to 12.1 RU6 MP1. It is, therefore,
affected by the following vulnerabilities :

  - A flaw exists in the password reset functionality that
    allows a remote attacker, using a crafted password reset
    action, to generate a new administrative session, thus
    bypassing authentication. (CVE-2015-1486)

  - A flaw exists related to filename validation in a
    console session that allows an authenticated, remote
    attacker to write arbitrary files. (CVE-2015-1487)

  - A flaw exists in an unspecified action handler that
    allows an authenticated, remote attacker to read
    arbitrary files. (CVE-2015-1488)

  - An unspecified flaw exists that allows an authenticated,
    remote attacker to manipulate SEPM services and gain
    elevated privileges. (CVE-2015-1489)

  - A flaw exists that allows traversing outside of a
    restricted path, due to a failure to properly sanitize
    user-supplied input. An authenticated, remote attacker,
    using a specially crafted installation package, can
    exploit this to access files outside of the restricted
    path. (CVE-2015-1490)

  - A SQL injection vulnerability exists due to a failure to
    properly sanitize user-supplied input before building
    SQL queries. An authenticated, remote attacker can
    exploit this to disclose or manipulate data in the
    back-end database. (CVE-2015-1491)

  - A flaw in how Symantec Endpoint Protection clients load
    dynamic-link libraries allows an authenticated attacker
    to replace legitimate client libraries with malicious
    ones, thus injecting executable code. (CVE-2015-1492)

  - A flaw exists in the /servlet/AgentServlet script due to
    improper sanitization of user-supplied input before
    using it in SQL queries. An unauthenticated, remote
    attacker can exploit this to inject or manipulate SQL
    queries against the back-end database, resulting in the
    disclosure or manipulation of arbitrary data.
    (VulnDB 135139)

  - A flaw exists in the SecurityAlertNotifyTask class due
    to improper sanitization of user-supplied input. An
    authenticated, remote attacker can exploit this to
    execute arbitrary commands. (VulnDB 135140)

  - A flaw exists in Rtvscan.exe related to searching and
    loading dynamic-link library (DLL) files due to using
    an insecure search path which may include directories
    that are not trusted or under the user's control. An
    attacker can exploit this, by injecting a crafted DLL
    file into path, to execute arbitrary code with the
    privileges of the user. (VulnDB 135141)");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20150730_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8fc576ad");
  # http://codewhitesec.blogspot.com/2016/02/symantec-endpoint-protection-legacy-edition.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77f4e0a0");
  # http://codewhitesec.blogspot.ca/2015/07/symantec-endpoint-protection.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d485ec4a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Endpoint Protection Manager version 12.1 RU6 MP1
or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Symantec Endpoint Protection Manager Authentication Bypass and Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_protection_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("symantec_endpoint_prot_mgr_installed.nasl");
  script_require_keys("installed_sw/Symantec Endpoint Protection Manager");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'Symantec Endpoint Protection Manager';

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

version = install['version'];
path    = install['path'   ];

fixed_ver = '12.1.6306.6100';

if (version =~ "^(12\.1|11\.0)(\.|$)" && ver_compare(ver:version, fix:fixed_ver, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port)
    port = 445;

  items = make_array("Path", path, "Installed version", version, "Fixed version", fixed_ver);
  order = make_list("Path", "Installed version", "Fixed version");

  report = report_items_str(report_items:items, ordered_fields:order);
  security_report_v4(port:port, extra:report, sqli:TRUE, severity:SECURITY_HOLE);
  exit(0);
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
