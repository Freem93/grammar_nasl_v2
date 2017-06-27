#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83954);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/19 20:46:16 $");

  script_cve_id("CVE-2015-2053");
  script_bugtraq_id(74873);
  script_osvdb_id(118643);
  script_xref(name:"IAVA", value:"2015-A-0129");
  script_xref(name:"MCAFEE-SB", value:"SB10094");

  script_name(english:"McAfee Managed Agent 4.6.x < 4.8.0.1938 / 5.0.x < 5.0.1 Log View Clickjacking (SB10094) (credentialed check)");
  script_summary(english:"Checks version of McAfee Framework Service.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an agent installed that is affected by a
clickjacking vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote host has a
version of McAfee Agent (MA) installed that is 4.6.x prior to
4.8.0.1938 or 5.0.x prior to 5.0.1. It is, therefore, affected by a
clickjacking vulnerability in the log viewing feature due to improper
validation of user-supplied input. A remote attacker can exploit this,
via a crafted web page, to compromise the application or obtain
sensitive information.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10094");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee Agent 4.8.0 Patch 3 (4.8.0.1938) or 5.0.1 per the
vendor advisory.

As a workaround, it is possible to partially mitigate the vulnerability
by adjusting the Agent policy to only allow connections from the ePO
server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:mcafee_agent");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_cma_installed.nbin");
  script_require_keys("installed_sw/McAfee Agent", "SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}

include("audit.inc");
include("install_func.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

appname = "McAfee Agent";

install = get_single_install(app_name: appname, exit_if_unknown_ver: TRUE);

report_adem = '';

if (report_paranoia < 2)
{
  sysdrive = hotfix_get_systemdrive(as_dir:TRUE);

  os = get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

  if (os >< "5.2")
    file = sysdrive + "\Documents and Settings\All Users\Application Data\McAfee\Common Framework\Agent.ini";
  else
    file = sysdrive + "\ProgramData\McAfee\Common Framework\Agent.ini";

  agent_file = hotfix_get_file_contents(path: file);

  if (agent_file['error'] == HCF_NOENT)
    report_adem = '\n  The Agent.ini could not be found. Testing for the' +
                  '\n  bListenToEPOServerOnly setting was not commited.\n';
  else if (agent_file['error'] != HCF_NOENT)
    hotfix_handle_error(error_code:agent_file['error'],
                        file:file,
                        appname:appname,
                        exit_on_fail:TRUE);

  hotfix_check_fversion_end();

  if ("bListenToEPOServerOnly=1" >< agent_file['data'])
    exit(0, "McAfee Managed Agent is set to accept connections only from the ePO server.");
  else
    report_adem = '\n  The bListenToEPOServerOnly within the Agent.ini was set to 0.' +
                  '\n  the Agent is not set to accept connections only from the ePO server.\n';
}
else
  report_adem = '\n  The bListenToEPOServerOnly was not test due to the scan being set to Paranoid.\n';

path = install['path'];
ver = install['version'];

fix = '';

if ((ver_compare(ver:ver, fix:"4.6.0", strict:FALSE) >= 0) &&
    (ver_compare(ver:ver, fix:"4.8.0.1938", strict:FALSE) < 0)
) fix = '4.8.0.1938';

if (ver =~ "^5\.0(\.|$)" && ver_compare(ver:ver, fix:"5.0.1", strict:FALSE) == -1)
  fix = '5.0.1';

if (!empty(fix))
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

    if (!empty(report_adem))
      report += report_adem;

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, ver, path );
