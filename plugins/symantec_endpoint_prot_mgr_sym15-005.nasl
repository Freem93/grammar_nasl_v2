#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84368);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/08/09 04:39:17 $");

  script_cve_id("CVE-2014-9227", "CVE-2014-9228", "CVE-2014-9229");
  script_bugtraq_id(75202, 75203, 75204);
  script_osvdb_id(123436, 123437, 123438);

  script_name(english:"Symantec Endpoint Protection Manager < 12.1 RU6 Multiple Vulnerabilities (SYM15-005)");
  script_summary(english:"Checks the SEPM version.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Symantec Endpoint Protection Manager installed on the
remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Endpoint Protection Manager (SEPM) installed
on the remote host is prior to 12.1 RU6. It is, therefore, affected by
the following vulnerabilities :

  - A DLL injection vulnerability exists due to improper
    path restrictions when loading DLLs. An authenticated,
    local attacker can exploit this to insert malicious DLL
    files, resulting in the execution of arbitrary code with
    system permissions. (CVE-2014-9227)

  - A denial of service vulnerability exists due to a
    deadlock condition in the 'sysplant.sys' file. A local
    attacker can exploit this by using a specially formatted
    call to cause the Windows system to be unable to fully
    shut down. Resolution of this condition requires a hard
    power cycle to restart the system. (CVE-2014-9228)

  - A blind SQL injection vulnerability exists due to the
    improper validation of input to scripts used by the
    management console. An authenticated, remote attacker
    can exploit this, using arbitrary SQL queries, to access
    or modify data in the back-end database. (CVE-2014-9229)");
  # https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20150617_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a0b15fd");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Endpoint Protection Manager 12.1 RU6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_protection_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

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
path    = install['path'];

fixed_ver = '12.1.6168.6000';

if (ver_compare(ver:version, fix:fixed_ver, strict:FALSE) == -1)
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
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
