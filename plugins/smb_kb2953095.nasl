#
# (C) Tenable Network Security, Inc.
#

# @DEPRECATED@
#
# Disabled on 2014/04/08.  Deprecated by smb_nt_ms14-017.nasl
#

include("compat.inc");

if (description)
{
  script_id(73161);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/06/03 17:46:08 $");

  script_cve_id("CVE-2014-1761");
  script_bugtraq_id(66385);
  script_osvdb_id(104895);

  script_name(english:"MS KB2953095: Vulnerability in Microsoft Word Could Allow Remote Code Execution");
  script_summary(english:"Checks for Microsoft 'Fix it'.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing one of the workarounds referenced in KB
2953095.

The remote host has a version of Microsoft Word installed that is
potentially affected by a code execution vulnerability due to the way
the application handles specially crafted RTF files.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/2953095");
  script_set_attribute(attribute:"solution", value:
"Microsoft has provided a workaround for Microsoft Word 2003, 2007,
2010, 2013, Word Viewer and Office Compatibility Pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "microsoft_emet_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

# Deprecated.
exit(0, "This plugin has been deprecated. Use plugin #73413 (smb_nt_ms14-017.nasl) instead.");


include("audit.inc");
include("global_settings.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);
vuln = FALSE;

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# Check for Office, Office Compat Pack
office_vers = hotfix_check_office_version();
office = make_list();
if (office_vers['11.0'])
{
  sp = get_kb_item('SMB/Office/2003/SP');
  if (int(sp) == 3)
  {
    affected = TRUE;
    office = make_list(office, '11');
  }
}
if (office_vers['12.0'])
{
  sp = get_kb_item('SMB/Office/2007/SP');
  if (int(sp) == 3)
  {
    affected = TRUE;
    office = make_list(office, '12');
  }
}
if (office_vers['14.0'])
{
  office2010sp = get_kb_item('SMB/Office/2010/SP');
  if (int(office2010sp) == 1 || int(office2010sp) == 2)
  {
    affected = TRUE;
    office = make_list(office, '14');
  }
}
if (office_vers['15.0'])
{
  office2013sp = get_kb_item('SMB/Office/2013/SP');
  if (int(office2013sp) == 0)
  {
    affected = TRUE;
    office = make_list(office, '15');
  }
}

if (!affected && (get_kb_list('SMB/Office/WordViewer/*/ProductPath')))
  affected = TRUE;

if (!affected) exit(0, 'No Office installs were found on the remote host.');
RegCloseKey(handle:hklm);

# First check mitigation per user
hku = registry_hive_connect(hive:HKEY_USERS, exit_on_fail:TRUE);
subkeys = get_registry_subkeys(handle:hku, key:'');

info_user_settings = '';
foreach key (subkeys)
{
  if ('.DEFAULT' >< key || 'Classes' >< key ||
      key =~ "^S-1-5-\d{2}$") # skip built-in accounts
    continue;

  # In case there are multiple versions of Office installed
  foreach ver (office)
  {
    if ('11.0' >< ver)
      res = get_registry_value(handle:hku, item:key + '\\Software\\Microsoft\\Office\\' + ver + '.0\\Word\\Security\\FileOpenBlock\\RtfFiles');
    else
      res = get_registry_value(handle:hku, item:key + '\\Software\\Microsoft\\Office\\' + ver + '.0\\Word\\Security\\FileBlock\\RtfFiles');
    if (!res)
    {
      info_user_settings += '\n    ' + key;
      break;
    }
  }
}
RegCloseKey(handle:hku);
close_registry();

# Check for EMET
emet_installed = FALSE;

if (!isnull(get_kb_item("SMB/Microsoft/EMET/Installed")))
  emet_installed = TRUE;

# Check if EMET is configured with Office, and
# the Office compat pack
emet_configured = make_array();
wordviewers = get_kb_list('SMB/Office/WordViewer/*/ProductPath');

if (max_index(keys(office)) > 0)
{
  for (i=0; i < max_index(office); i++)
  {
    item = office[i];
    if (path = get_kb_item('SMB/Office/Word/'+item+'.0/Path'))
    {
      path = str_replace(find:"\\", replace:'\\', string:path);
      emet_configured[path + "winword.exe"] = FALSE;
      emet_configured[path + "outlook.exe"] = FALSE;
    }
    foreach viewer (keys(wordviewers))
    {
      if ('WordViewer/'+item+'.0' >< viewer)
      {
        path = wordviewers[viewer];
        path = str_replace(find:"\\", replace:'\\', string:path);
        emet_configured[path + "wordview.exe"] = FALSE;
      }
    }
  }
}



emet_list = get_kb_list("SMB/Microsoft/EMET/*");
if (!isnull(emet_list))
{
  foreach entry (keys(emet_list))
  {
    foreach item (keys(emet_configured))
    {
      if (
        (tolower(item) >< tolower(entry) ||
         ('winword.exe' >< item && '*\\office1*\\winword.exe' >< entry) ||
         ('outlook.exe' >< item && '*\\office1*\\outlook.exe' >< entry)
        ) && 
        '/dep' >< entry)
      {
        dep = get_kb_item(entry);
        if (!isnull(dep) && dep == 1)
          emet_configured[item] = TRUE;
      }
    }
  }
}

# Check if any of the applications are not
# configured with emet
info = '';
emet_info = '';
if (!emet_installed)
{
  emet_info =
    'Microsoft Enhanced Mitigation Experience Toolkit (EMET)' +
    '\nis not installed.\n';
}
else
{
  foreach item (keys(emet_configured))
  {
    if (!emet_configured[item])
      info += '  Application : ' + item + '\n';
  }
  if (info)
  {
    emet_info =
      'Microsoft Enhanced Mitigation Experience Toolkit (EMET) is' +
      '\ninstalled, however the following applications are not configured' +
      '\nwith EMET :\n' +
      info;
  }
}

if (info_user_settings)
{
  port = kb_smb_transport();
  if (report_verbosity > 0)
  {
    report += 
      '\nThe following users have vulnerable Office settings :' + 
      info_user_settings;
  
    if(emet_info)
      report += '\n\nFurther, the ' + emet_info;
    else report += '\n';

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
exit(0, 'Note that this check may not be complete, as Nessus can only check the\nSIDs of logged on users.');




