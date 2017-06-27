#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31733);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/06/09 16:51:55 $");

  script_cve_id("CVE-2008-1357");
  script_bugtraq_id(28228);
  script_osvdb_id(42853);
  script_xref(name:"Secunia", value:"29337");

  script_name(english:"McAfee Common Management Agent 3.6.0 UDP Packet Handling Format String (credentialed check)");
  script_summary(english:"Checks version of McAfee CMA");

  script_set_attribute(attribute:"synopsis", value:
"A remote service is affected by a format string vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a Common Management Agent, a component of
the ePolicy Orchestrator system security management solution from
McAfee. 

The version of the Common Management Agent on the remote host is earlier
than 3.6.0.595 and, as such, contains a format string vulnerability.  If
configured with a debug level of 8 (its highest level but not the
default), an unauthenticated, remote attacker may be able to leverage
this issue by sending a specially crafted UDP packet to the agent
broadcast port to crash the service or even execute arbitrary code on
the affected host.");
  script_set_attribute(attribute:"see_also", value:"http://aluigi.altervista.org/adv/meccaffi-adv.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/489476/100/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Apply Hotfix BZ398370 Build 595 for Common Management Agent 3.6.0 Patch
3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:W/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(134);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:common_management_agent");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("mcafee_cma_installed.nbin");
  script_require_keys("installed_sw/McAfee Agent");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

appname = "McAfee Agent";

install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);

loglevel = install['Log Level'];

# check log level unless running paranoid scan
if (report_paranoia < 2)
  if (isnull(loglevel) || loglevel < 8) audit(AUDIT_PARANOID);

ver  = install['version'];
path = install['path'];

fix = "3.6.0.595";

if (ver_compare(ver:ver, fix:fix, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';

    if (report_paranoia > 1)
    {
      report +=
      '\nNote, though, that Nessus did not check the value of the debug level' +
      '\nbecause of the Report Paranoia setting in effect when this scan was' +
      '\nrun.\n';
    }
    else
    {
      report +=
      '\nMoreover, Nessus has verified the debug level currently is set to ' + loglevel + '.\n';
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port:port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, ver, path );
