#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86873);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/03/28 04:28:40 $");

  script_cve_id(
    "CVE-2015-1492",
    "CVE-2015-6554",
    "CVE-2015-6555",
    "CVE-2015-8113"
  );
  script_bugtraq_id(
    76083,
    77494,
    77495
  );
  script_osvdb_id(
    125668,
    129984,
    129985
  );

  script_name(english:"Symantec Endpoint Protection Manager < 12.1 RU6 MP3 Multiple Vulnerabilities (SYM15-011)");
  script_summary(english:"Checks the SEPM version.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Symantec Endpoint Protection Manager installed on the
remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Endpoint Protection Manager (SEPM) installed
on the remote host is prior to 12.1 RU6 MP3. It is, therefore,
affected by the following vulnerabilities :

  - A local privilege escalation vulnerability exists due to
    an untrusted search path flaw. A local attacker can
    exploit this, via a trojan DLL in a client install
    package, to gain privileges. (CVE-2015-1492,
    CVE-2015-8113)

  - A remote command execution vulnerability exists due to
    an unspecified flaw in the management console. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary Java
    commands. (CVE-2015-6554)

  - An arbitrary code execution vulnerability exists due to
    an unspecified flaw in the management console. An
    authenticated, remote attacker can exploit this by
    connecting to the console Java port, to execute
    arbitrary code with administrator privileges.
    (CVE-2015-6555)");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20151109_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec8306d3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Endpoint Protection Manager 12.1 RU6 MP3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/13");

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

fixed_ver = '12.1.6306.6300';

if (version =~ "^12\.1\." && ver_compare(ver:version, fix:fixed_ver, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : '+ path +
      '\n  Installed version : '+ version +
      '\n  Fixed version     : '+ fixed_ver +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
