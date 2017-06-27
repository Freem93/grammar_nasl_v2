#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62311);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/11 13:32:18 $");

  script_cve_id("CVE-2012-2515", "CVE-2012-2516");
  script_bugtraq_id(36546, 40969, 55265);
  script_osvdb_id(58423, 83310, 83311);
  script_xref(name:"EDB-ID", value:"9803");
  script_xref(name:"ICSA", value:"12-131-02");

  script_name(english:"KeyWorks KeyHelp ActiveX Control Multiple Vulnerabilities");
  script_summary(english:"Checks for kill bits");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an ActiveX control installed that has multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has KeyWorks KeyHelp ActiveX control installed, which
is affected by multiple vulnerabilities :

  - Multiple stack-based buffer overflows exist that could 
    allow an attacker to execute arbitrary code. 
    (CVE-2012-2515)

  - An unspecified command injection vulnerability. 
    (CVE-2012-2516)"
  );
  script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/9sg_emc_keyhelp.html");
  script_set_attribute(attribute:"see_also", value:"http://sotiriu.de/adv/NSOADV-2010-008.txt");
  script_set_attribute(attribute:"solution", value:"Remove or disable the control as it is no longer supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'KeyHelp ActiveX LaunchTriPane Remote Code Execution Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:keyworks:keyhelp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("smb_activex_func.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');
if (activex_init() != ACK_OK) audit(AUDIT_FN_FAIL, 'activex_init');

info = "";
installs = 0;

clsids = make_list(
  '{1E57C6C4-B069-11D3-8D43-00104B138C8C}',
  '{45E66957-2932-432A-A156-31503DF0A681}',
  '{B7ECFD41-BE62-11D2-B9A8-00104B138C8C}'
);

info = '';
foreach clsid (clsids)
{
  file = activex_get_filename(clsid:clsid);
  if (isnull(file))
  {
    activex_end();
    exit(1, "activex_get_filename() returned NULL.");
  }

  if (!file) continue;

  installs++;

  # Get its version.
  version = activex_get_fileversion(clsid:clsid);
  if (isnull(version))
  {
    activex_end();
    audit(AUDIT_VER_FAIL, file);
  }

  if (version == '') version = 'unknown';

  # And check it.
  if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
  {
    info += 
      '\n  Class identifier  : ' + clsid +
      '\n  Filename          : ' + file +
      '\n  Installed version : ' + version + '\n';
  }
}
activex_end();
if (!installs) exit(0, 'None of the affected CLSIDs were found on the remote host.');


# Report findings.
if (info)
{
  # At this point, we want to know how many *vulnerable* installs there are.
  installs = max_index(split(info)) / 4;

  if (report_paranoia > 1)
  {
    if (installs == 1)
      report = info +
        '\n' +
        '\nNote, though, that Nessus did not check whether the kill bit was set' +
        '\nfor the control\'s CLSID because of the Report Paranoia setting in' +
        '\neffect when this scan was run.\n';
    else
      report = info +
        '\n' +
        '\nNote, though, that Nessus did not check whether the kill bits were set' +
        '\nfor the controls\' CLSIDs because of the Report Paranoia setting in' +
        '\neffect when this scan was run.\n';
  }
  else
  {
    if (installs == 1)
      report = info +
        '\n' +
        '\nMoreover, its kill bit is not set so it is accessible via Internet' +
        '\nExplorer.\n';
    else
      report = info +
        '\n' +
        '\nMoreover, their kill bits are not set so they are accessible via' +
        '\nInternet Explorer.\n';
  }

  if (report_verbosity > 0) security_hole(port:kb_smb_transport(), extra:report);
  else security_hole(kb_smb_transport());
  exit(0);
}
else 
{
  if (installs == 1) exit(0, 'One of the controls is installed but its kill bit is set.');
  else exit(0, 'The controls are installed but their kill bits are set.');
}
