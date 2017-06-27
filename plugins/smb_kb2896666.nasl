#
# (C) Tenable Network Security, Inc.
#

#@DEPRECATED@
#
# Disabled on 2013/12/11.  Deprecated by smb_nt_ms13-096.nasl

include("compat.inc");

if (description)
{
  script_id(70773);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/06/14 00:01:15 $");

  script_cve_id("CVE-2013-3906");
  script_bugtraq_id(63530);
  script_osvdb_id(99376);

  script_name(english:"MS KB2896666: Vulnerability in Microsoft Graphics Component Could Allow Remote Code Execution (deprecated)");
  script_summary(english:"Checks for Workaround");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing one of the workarounds referenced in KB
2896666. 

The remote host has a version of the Microsoft Graphics Component
installed that is potentially affected by a code execution vulnerability
due to the way the application handles specially crafted TIFF images.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/2896666");
  script_set_attribute(attribute:"solution", value:
"Microsoft has provided a workaround for Windows Vista, 2008, Office
2003, Office 2007, Office 2010, Office Compatibility Pack, Lync 2010 and
Lync 2013.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Tagged Image File Format (TIFF) Integer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "microsoft_emet_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}

exit(0, "This plugin has been deprecated. Use smb_nt_ms13-096.nasl (plugin ID 71311) instead.");

include("audit.inc");
include("global_settings.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);
vuln = FALSE;

arch = get_kb_item_or_exit('SMB/ARCH', exit_code:1);
if (arch == 'x64') extra = "\Wow6432Node";

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# Check if the OS is Vista / 2008
affected = FALSE;
if (hotfix_check_sp_range(vista:'2') > 0) affected = TRUE;

# Check for Office, Office Compat Pack, or Lync
office_vers = hotfix_check_office_version();
office = make_list();
if (!affected && office_versions['11.0'])
{
  sp = get_kb_item('SMB/Office/2003/SP');
  if (int(sp) == 3)
  {
    affected = TRUE;
    office = make_list(office, '11');
  }
}
if (!affected && office_versions['12.0'])
{
  sp = get_kb_item('SMB/Office/2007/SP');
  if (int(sp) == 3)
  {
    affected = TRUE;
    office = make_list(office, '12');
  }
}
if (!affected && office_versions['13.0'])
{
  office2010sp = get_kb_item('SMB/Office/2010/SP');
  if (int(office2010sp) == 1 || int(office2010sp) == 2)
  {
    affected = TRUE;
    office = make_list(office, '13');
  }
}

if (!affected && (get_kb_list('SMB/Office/WordViewer/*/ProductPath') || get_kb_list('SMB/Office/PowerPointViewer/*/ProductPath')))
  affected = TRUE;

lync2010_path = get_registry_value(handle:hklm, item:'SOFTWARE'+extra+"\Microsoft\Communicator\InstallationDirectory");
lync2010_att_admin_path = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\AttendeeCommunicator\InstallationDirectory");
lync2013_path = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\Office\15.0\Lync\InstallationDirectory");

if (!affected && (lync2010_path || lync2010_att_admin_path || lync2013_path)) affected = TRUE;

if (!affected) exit(0, 'No affected operating systems or applications were found on the remote host.');

# First check for the TIFF codec workaround
ret = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\Gdiplus\DisableTIFFCodec");
if (!isnull(ret) && ret == 1) exit(0, 'The host is not affected since the \'DisableTIFFCodec\' workaround has been applied.');
RegCloseKey(handle:hklm);
close_registry();

# Check for EMET
emet_installed = FALSE;

if (!isnull(get_kb_item("SMB/Microsoft/EMET/Installed")))
  emet_installed = TRUE;

# Check if EMET is configured with Office, Lync, and
# the Office compat pack
emet_configured = make_array();
wordviewers = get_kb_list('SMB/Office/WordViewer/*/ProductPath');
pptviewers = get_kb_list('SMB/Office/PowerPointViewer/*/ProductPath');

if (max_index(keys(office)) > 0)
{
  for (i=0; i < max_index(office); i++)
  {
    item = office[i];
    if (path = get_kb_item('SMB/Office/Word/'+item+'.0/Path'))
    {
      path = str_replace(find:"\\", replace:'\\', string:path);
      emet_configured[path + "word.exe"] = FALSE;
    }
    if (path = get_kb_item('SMB/Office/Excel/'+item+'.0/Path'))
    {
      path = str_replace(find:"\\", replace:'\\', string:path);
      emet_configured[path + "excel.exe"] = FALSE;
    }
    if (path = get_kb_item('SMB/Office/Powerpoint/'+item+'.0/Path'))
    {
      path = str_replace(find:"\\", replace:'\\', string:path);
      emet_configured[path + "powerpoint.exe"] = FALSE;
    }
    if (path = get_kb_item('SMB/Office/Infopath/'+item+'.0/Path'))
    {
      path = str_replace(find:"\\", replace:'\\', string:path);
       emet_configured[path + "infopath.exe"] = FALSE;
    }
    if (path = get_kb_item('SMB/Office/Outlook/'+item+'.0/Path'))
    {
      path = str_replace(find:"\\", replace:'\\', string:path);
      emet_configured[path + "outlook.exe"] = FALSE;
    }
    if (path = get_kb_item('SMB/Office/Publisher/'+item+'.0/Path'))
    {
      path = str_replace(find:"\\", replace:'\\', string:path);
       emet_configured[path + "publisher.exe"] = FALSE;
     }
    if (path = get_kb_item('SMB/Office/Onenote/'+item+'.0/Path'))
    {
      path = str_replace(find:"\\", replace:'\\', string:path);
      emet_configured[path + "onenote.exe"] = FALSE;
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
    foreach viewer (keys(pptviewers))
    {
      if ('PowerPointViewer/'+item+'.0' >< viewer)
      {
        path = pptviewers[viewer];
        path = str_replace(find:"\\", replace:'\\', string:path);
        emet_configured[path + "pptview.exe"] = FALSE;
      }
    }
  }
}

if (lync2010_path || lync2010_att_admin_path)
  emet_configured['communicator.exe'] = FALSE;

if (lync2013_path)
  emet_configured['lync.exe'] = FALSE;

emet_list = get_kb_list("SMB/Microsoft/EMET/*");
if (!isnull(emet_list))
{
  foreach entry (keys(emet_list))
  {
    foreach item (keys(emet_configured))
    {
      if (tolower(item) >< tolower(entry) && '/dep' >< entry)
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
    'Microsoft Enhanced Mitigation Experience Toolkit (EMET) is not' +
    '\ninstalled.\n';
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
      '\nwith EMET :' +
      info;
  }
}

port = kb_smb_transport();

if (report_verbosity > 0)
{
  report =
    '\nThe remote host is missing the disable TIFF codec workaround.';

  if(emet_info)
    report += 'Further\nthe ' + emet_info;
  else report += '\n';

  security_hole(port:port, extra:report);
}
else security_hole(port);
