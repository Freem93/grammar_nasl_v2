
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(58482);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2012/08/06 19:18:40 $");

  script_bugtraq_id(52673);
  script_osvdb_id(80297);
  script_xref(name:"EDB-ID", value:"18641");

  script_name(english:"Cisco Linksys PlayerPT ActiveX SetSource() Method base64string Argument Parsing Remote Overflow");
  script_summary(english:"Checks if the kill bit is set");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has an ActiveX control that is affected by a
buffer overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The install of the Cisco Linksys PlayerPT ActiveX control on the
remote Windows host reportedly has a stack-based buffer overflow
vulnerability that can be triggered by a specially crafted argument to
the 'base64string' argument of the its SetSource() method. 

By tricking a user into opening a specially crafted web page, a
remote, unauthenticated attacker could execute arbitrary code on the
remote host subject to the user's privileges."
  );
  script_set_attribute(
    attribute:"solution",
    value:"Remove or disable the control as fixes are not available."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Cisco Linksys PlayerPT ActiveX Control Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:cisco:linksys_playerpt_activex_control");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");
include("smb_activex_func.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (activex_init() != ACX_OK) exit(1, 'activex_init() failed.');

clsid = '{9E065E4A-BD9D-4547-8F90-985DC62A5591}';

# Make sure the control is installed
file = activex_get_filename(clsid:clsid);
if (isnull(file))
{
  activex_end();
  exit(1, "activex_get_filename() returned NULL.");
}
if (!file)
{
  activex_end();
  exit(0, "The control is not installed since the class id '"+clsid+"' is not defined on the remote host.");
}

# Get its version
version = activex_get_fileversion(clsid:clsid);
if (!version) version = 'unknown';

info = "";
if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
{
  info +=
    '\n  Class identifier  : ' + clsid +
    '\n  Filename          : ' + file +
    '\n  Installed version : ' + version + '\n';
}
activex_end();

# Report findings.
if (info)
{
  if (report_paranoia > 1)
  {
    report = info +
      '\n' +
      'Note, though, that Nessus did not check whether the kill bit was\n' +
      "set for the control's CLSID because of the Report Paranoia setting" + '\n' +
      'in effect when this scan was run.\n';
  }
  else
  {
    report = info +
      '\n' +
      'Moreover, its kill bit is not set so it is accessible via Internet\n' +
      'Explorer.\n';
  }

  if (report_verbosity > 0) security_hole(port:kb_smb_transport(), extra:report);
  else security_hole(kb_smb_transport());

  exit(0);
}
else exit(0, "The control is installed, but its kill bit is set.");
