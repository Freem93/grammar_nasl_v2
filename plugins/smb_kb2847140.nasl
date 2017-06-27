#@DEPRECATED@
#
# Disabled on 2013/05/15.  Deprecated by smb_nt_ms13-038.nasl

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66329);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/06/03 17:46:08 $");

  script_cve_id("CVE-2013-1347");
  script_bugtraq_id(59641);
  script_osvdb_id(92993);
  script_xref(name:"CERT", value:"237655");

  script_name(english:"MS KB2847140: Vulnerability in Internet Explorer 8 Could Allow Remote Code Execution (deprecated)");
  script_summary(english:"Checks if workarounds referenced in KB article have been applied.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is affected by a remote code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is missing one of the workarounds referenced in KB
2847140. 

The remote version of IE reportedly has a use-after-free flaw related to
how CGenericElement objects are handled that could result in arbitrary
code execution on the remote system.

This plugin has been deprecated due to the publication of MS13-038.
Microsoft has released updates that make the workarounds unnecessary.
To check for those, use Nessus plugin ID 66413.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/2847140");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the IE settings workarounds suggested by Microsoft in the
advisory, or apply the MSHTML Shim workaround in the Microsoft
'Fix it' solution."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Internet Explorer CGenericElement Object Use-After-Free Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/09");
  
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("microsoft_emet_installed.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}
exit(0, 'This plugin has been deprecated.  Use smb_nt_ms13-038.nasl (plugin ID 66413) instead.');

include('audit.inc');
include('global_settings.inc');
include("smb_hotfixes.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");

if (hotfix_check_server_core() == 1)
  audit(AUDIT_WIN_SERVER_CORE);

# Only IE 8 is affected
version = get_kb_item_or_exit("SMB/IE/Version");
v = split(version, sep:".", keep:FALSE);
if (int(v[0]) != 8)
 exit(0, "IE version "+ version + " is not known to be affected.");

registry_init();

hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

systemroot = hotfix_get_systemroot();
if(!systemroot) audit(AUDIT_FN_FAIL, 'hotfix_get_systemroot');

guid = '{d1bc5fb9-8846-4c1c-98d0-2d415d4c6df6}';
path = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\" + guid);
RegCloseKey(handle:hklm);

if (isnull(path))
  path = systemroot + "\AppPatch\Custom\" + guid + '.sdb';

# Now make sure the file is in place
if (hotfix_file_exists(path:path))
{
  hotfix_check_fversion_end();
  exit(0, "The host is not affected since the Microsoft 'Fix it' has been applied.");
}

# hotfix_file_exists calls NetUseDel(close:FALSE), so we must reconnect
registry_init();

emet_info = '';

emet_installed = FALSE;
emet_with_ie   = FALSE;

if (!isnull(get_kb_item("SMB/Microsoft/EMET/Installed")))
  emet_installed = TRUE;

# Check if EMET is configured with IE.
# The workaround does not specifically ask to enable DEP
# but if IE is configured with EMET, dep is enabled by default.

emet_list = get_kb_list("SMB/Microsoft/EMET/*");
if (!isnull(emet_list))
{
  foreach entry (keys(emet_list))
  {
    if ("iexplore.exe" >< entry && "/dep" >< entry)
    {
      dep = get_kb_item(entry);
      if (!isnull(dep) && dep == 1)
        emet_with_ie = TRUE;
    }
  }
}

if (!emet_installed)
{
  emet_info =
  '\n  Microsoft Enhanced Mitigation Experience Toolkit (EMET) is not' +
  '\n  installed.';
}
else if (emet_installed)
{
  if (!emet_with_ie)
  {
    emet_info =
    '\n  Microsoft Enhanced Mitigation Experience Toolkit (EMET) is' +
    '\n  installed, however Internet Explorer is not configured with EMET.';
  }
}

info_user_settings = '';

# check mitigation per user
hku = registry_hive_connect(hive:HKEY_USERS, exit_on_fail:TRUE);
subkeys = get_registry_subkeys(handle:hku, key:'');

foreach key (subkeys)
{
  if ('.DEFAULT' >< key || 'Classes' >< key ||
     key =~ "^S-1-5-\d{2}$") # skip built-in accounts
    continue;

  mitigation = FALSE;

# "Set Internet and Local intranet security zone settings to "High" to block ActiveX Controls and Active Scripting in these zones"
  key_part_intranet = '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\1\\CurrentLevel';
  key_part_internet = '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3\\CurrentLevel';

  value = get_registry_value(handle:hku, item:key + key_part_intranet);
  value1 = get_registry_value(handle:hku, item:key + key_part_internet);

  if (isnull(value) && isnull(value1))
    continue;

  # 0x00012000 = 73728 = High Security
  if (!isnull(value) && !isnull(value1) &&
     value == 73728 && value1 == 73728)
    mitigation = TRUE;

# "Configure Internet Explorer to prompt before running Active Scripting or to disable Active Scripting in the Internet and Local intranet security zone"
  key_part_intranet = '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\1\\1400';
  key_part_internet = '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3\\1400';

  value = get_registry_value(handle:hku, item:key + key_part_intranet);
  value1 = get_registry_value(handle:hku, item:key + key_part_internet);

  # 1 = prompt, 3 = disable
  if (!isnull(value) && !isnull(value1) &&
     (value == 1 || value == 3) && (value1 == 1 || value1 == 3))
    mitigation = TRUE;

  if (!mitigation)
    info_user_settings += '\n    ' + key + ' (Active Scripting Enabled)';
}

RegCloseKey(handle:hku);

hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# check if user settings have been overriden by what is in HKLM
# note: Security_HKLM_only can be set by group policy
value = get_registry_value(handle:hklm, item:'SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Security_HKLM_only');

if (info_user_settings != '' && !isnull(value) && value == 1)
{
  mitigation = FALSE;

# "Set Internet and Local intranet security zone settings to "High" to block ActiveX Controls and Active Scripting in these zones"
  key_part_intranet = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\1\\CurrentLevel';
  key_part_internet = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3\\CurrentLevel';

  value = get_registry_value(handle:hklm, item:key_part_intranet);
  value1 = get_registry_value(handle:hklm, item:key_part_internet);

  # 0x00012000 = 73728 = High Security
  if (!isnull(value) && !isnull(value1) &&
     value == 73728 && value1 == 73728)
    mitigation = TRUE;

# "Configure Internet Explorer to prompt before running Active Scripting or to disable Active Scripting in the Internet and Local intranet security zone"
  key_part_intranet = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\1\\1400';
  key_part_internet = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3\\1400';

  value = get_registry_value(handle:hklm, item:key_part_intranet);
  value1 = get_registry_value(handle:hklm, item:key_part_internet);

  # 1 = prompt, 3 = disable
  if (!isnull(value) && !isnull(value1) &&
     (value == 1 || value == 3) && (value1 == 1 || value1 == 3))
    mitigation = TRUE;

  if (mitigation)
    info_user_settings = '';
}

RegCloseKey(handle:hklm);

close_registry();

if (info_user_settings != '')
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    if (emet_info != '')
      report = 
      '\n  The remote host is missing the MSHTML Shim workaround and the' +
      '\n  following users have vulnerable IE settings :' + info_user_settings + '\n' + emet_info + '\n';
    else
      report = 
      '\n  The remote host is missing the MSHTML Shim workaround and the' +
      '\n  following users have vulnerable IE settings :' + info_user_settings + '\n';

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The host is not affected since a workaround has been applied.");
