#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54990);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/23 20:42:24 $");

  script_cve_id("CVE-2011-2217");
  script_bugtraq_id(48099);
  script_osvdb_id(73211);

  script_name(english:"Tom Sawyer Software GET Extension Factory COM Object Instantiation Memory Corruption");
  script_summary(english:"Checks for controls");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has a COM object that is affected by a memory
corruption vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Tom Sawyer Software's GET Extension Factory, a component used for
graph visualization applications, is installed on the remote Windows
host.  It may have been bundled with a third-party application, such
as the VMware Infrastructure Client or Embarcadero ER / Studio XE2.

The installed version of this component has a vulnerability in that it
does not initialize COM objects properly inside Internet Explorer,
which leads to a memory corruption vulnerability.

If an attacker can trick a user on the affected host into visiting a
specially crafted web page, this issue could be leveraged to execute
arbitrary code on the host subject to the user's privileges."
  );
  # https://labs.idefense.com/verisign/intelligence/2009/vulnerabilities/display.php?id=911
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d795b7de");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/Jun/38");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/Sep/49");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2011-0009.html");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2011/000141.html");
  script_set_attribute(
    attribute:"solution",
    value:
"If the affected COM object is installed with the VMware
Infrastructure Client, follow the instructions in VMware's advisory.

Otherwise, remove or disable the controls."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Tom Sawyer Software GET Extension Factory Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
installs = 0;


clsids = make_list(
  '{575B655F-FED4-4EE1-8F62-0A69D404F46B}',
  '{658ED6E7-0DA1-4ADD-B2FB-095F08091118}',     # Embarcadero ER/Studio XE2
  '{A2282403-50DE-4A2E-A118-B90AEDB1ADCC}'
);

info = '';
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
  installs++;

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
if (!installs) exit(0, 'None of the affected controls were found on the remote host.');


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
