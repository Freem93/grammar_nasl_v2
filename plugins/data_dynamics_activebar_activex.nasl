#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(54841);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/07 20:46:53 $");

  script_cve_id("CVE-2007-3883", "CVE-2011-1207");
  script_bugtraq_id(24959, 47643);
  script_osvdb_id(37692, 72136);
  script_xref(name:"Secunia", value:"26098");
  script_xref(name:"Secunia", value:"43399");
  script_xref(name:"Secunia", value:"43474");
  script_xref(name:"EDB-ID", value:"4190");
  script_xref(name:"EDB-ID", value:"5395");

  script_name(english:"Data Dynamics ActiveBar ActiveX Controls Code Execution");
  script_summary(english:"Checks for ActiveX control.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control installed that is
affected by a code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"One or more of the Data Dynamics ActiveBar ActiveX controls installed
on the remote Windows host is affected by a code execution
vulnerability due to unspecified issues in the 'Save()',
'SaveLayoutChanges()', 'SaveMenuUsageData()', and 'SetLayoutData()'
methods.

Note that Data Dynamics ActiveBar is bundled with IBM Rational System
Architect.");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21497689");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/2562937");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg24029808");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg24029810");
  script_set_attribute(attribute:"solution", value:
"Multiple solutions exist to resolve this vulnerability :

  - Upgrade to IBM Rational System Architect 11.3.1.4 (eGA
    29 April 2011) / 11.4.0.3 (eGA 29 April 2011) or later.

  - Install Microsoft KB2562937 (Update Rollup for ActiveX
    Kill Bits).

  - Disable the use of the vulnerable ActiveX controls
    within Internet Explorer per the IBM advisory.

  - Disable all ActiveX controls in the Internet Zone.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/27");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:datadynamics:activebar");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:rational_system_architect");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");
include("smb_activex_func.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');
if (activex_init() != ACK_OK) exit(1, 'activex_init() failed.');

info = "";
controlinstalled=FALSE;
clsids = make_list(
  '{E4F874A0-56ED-11D0-9C43-00A0C90F29FC}',
  '{4932CEF4-2CAA-11D2-A165-0060081C43D9}',
  '{5407153D-022F-4CD2-8BFF-465569BC5DB8}'
);

foreach clsid (clsids)
{
  file = activex_get_filename(clsid:clsid);
  if (isnull(file))
  {
    debug_print('activex_get_filename() returned NULL.');
    continue;
  }
  if (!file)
  {
    debug_print('The control is not installed as the class id \''+clsid+'\' does not exist on the remote host.');
    continue;
  }
  controlinstalled=TRUE;

  # Get its version.
  version = activex_get_fileversion(clsid:clsid);
  if (!version) version = 'unknown';

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
if (!controlinstalled) exit(0, 'None of the affected controls were found on the remote host.');

# Report findings.
if (info)
{
  if (report_paranoia > 1)
  {
    report = info +
      '\n' +
      '\nNote, though, that Nessus did not check whether the kill bit was set' +
      '\nfor the control\'s CLSID because of the Report Paranoia setting in' +
      '\neffect when this scan was run.\n';
  }
  else
  {
    report = info +
      '\n' +
      '\nMoreover, its kill bit is not set so it is accessible via Internet' +
      '\nExplorer.\n';
  }

  if (report_verbosity > 0) security_hole(port:kb_smb_transport(), extra:report);
  else security_hole(kb_smb_transport());
  exit(0);
}
else exit(0, 'One or more of the controls are installed but their kill bits are set.');
