#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71311);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/09 21:04:54 $");

  script_cve_id("CVE-2013-3906");
  script_bugtraq_id(63530);
  script_osvdb_id(99376);
  script_xref(name:"EDB-ID", value:"30011");
  script_xref(name:"MSFT", value:"MS13-096");

  script_name(english:"MS13-096: Vulnerability in Microsoft Graphics Component Could Allow Remote Code Execution (2908005)");
  script_summary(english:"Checks file versions");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host has a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft's Graphics Component installed on the remote
host is affected by a heap overflow vulnerability. Specially crafted
TrueType font files are not processed properly. A remote,
unauthenticated attacker could exploit this vulnerability by getting a
user to view content that contains malicious TrueType font files,
resulting in arbitrary code execution.

Note that this issue is currently being exploited by malware in the
wild.");
  # http://blogs.technet.com/b/srd/archive/2013/11/05/cve-2013-3906-a-graphics-vulnerability-exploited-through-word-documents.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?55e970ce");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-096");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2008, Windows
Vista, Office 2003, Office 2007, Office 2010, Office Compatibility
Pack, Lync 2010, Lync 2010 Attendee, Lync 2013, and Lync Basic 2013.

Note: KB2896666 was previously released for this issue. The fix for
KB2896666 can be removed after applying MS13-096 in order to view TIFF
files.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS13-096 Microsoft Tagged Image File Format (TIFF) Integer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync_basic");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

global_var bulletin, vuln;

# #########################
#
# Get list of all user Directories
#
# #########################
function get_user_dirs()
{
  local_var appdir, dirpat, domain, hklm, iter, lcpath, login, pass;
  local_var path, paths, pdir, port, rc, root, share, user, ver;

  paths = make_list();

  registry_init();
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  pdir = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\ProfilesDirectory");
  if (pdir && stridx(tolower(pdir), "%systemdrive%") == 0)
  {
    root = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot");
    if (!isnull(root))
    {
      share = hotfix_path2share(path:root);
      pdir = share - '$' + ':' + substr(pdir, strlen("%systemdrive%"));
    }
  }
  RegCloseKey(handle:hklm);
  close_registry(close:FALSE);

  if (!pdir)
    return NULL;

  ver = get_kb_item_or_exit("SMB/WindowsVersion");

  share = hotfix_path2share(path:pdir);
  dirpat = ereg_replace(string:pdir, pattern:"^[A-Za-z]:(.*)", replace:"\1\*");

  port    =  kb_smb_transport();
  if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
  login   =  kb_smb_login();
  pass    =  kb_smb_password();
  domain  =  kb_smb_domain();

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel(close:FALSE);
    return NULL;
  }

  # 2000 / XP / 2003
  if (ver < 6)
    appdir += "\Local Settings\Application Data";
  # Vista / 7 / 2008
  else
    appdir += "\AppData\Local";

  paths = make_array();
  iter = FindFirstFile(pattern:dirpat);
  while (!isnull(iter[1]))
  {
    user = iter[1];
    iter = FindNextFile(handle:iter);

    if (user == "." || user == "..")
      continue;

    path = pdir + '\\' + user + appdir;

    lcpath = tolower(path);
    if (isnull(paths[lcpath]))
      paths[lcpath] = path;
  }

  NetUseDel(close:FALSE);

  return paths;
}


# #########################
#
# Get file version
#
# #########################
function get_ver()
{
  local_var fh, path, rc, share, ver;

  path = _FCT_ANON_ARGS[0];
  share = hotfix_path2share(path:path);

  rc = NetUseAdd(share:share);
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL, share);
  }

  ver = NULL;
  path = ereg_replace(string:path, pattern:"^[A-Za-z]:(.*)", replace:'\\1\\');

  fh = CreateFile(
    file               : path,
    desired_access     : GENERIC_READ,
    file_attributes    : FILE_ATTRIBUTE_NORMAL,
    share_mode         : FILE_SHARE_READ,
    create_disposition : OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);
    ver = join(ver, sep:".");
    CloseFile(handle:fh);
  }

  NetUseDel(close:FALSE);

  return ver;
}


# #########################
#
# Check if a file path/version is vulnerable
#
# #########################
function check_vuln(fix, kb, name, path, ver, min_ver)
{
  local_var info;

  if (isnull(ver))
    ver = get_ver(path);

  if (isnull(ver) || ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
    return 0;

  # If min_ver is supplied, make sure the version is higher than the min_ver
  if (min_ver && ver_compare(ver:ver, fix:min_ver, strict:FALSE) == -1)
    return 0;

  info =
    '\n  Product           : ' + name +
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix + '\n\n';
  hotfix_add_report(info, bulletin:bulletin, kb:kb);

  vuln = TRUE;
}

function _is_accessible_share()
{
  local_var path, share;
  path = _FCT_ANON_ARGS[0];

  if (isnull(path))
    return FALSE;

  share = hotfix_path2share(path:path);
  if (is_accessible_share(share:share)) return TRUE;

  if (vuln)
    return FALSE;

  # only exit if nothing there is nothing to report (nothing has already been
  # identified as vulnerable)
  hotfix_check_fversion_end();
  audit(AUDIT_SHARE_FAIL, share);
}

# #########################
#
# Main
#
# #########################
get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');
bulletin = 'MS13-054';
kbs = make_list(
  '2901674', # Windows Vista / 2008
  '2850047', # Office 2003 / Word Viewer
  '2817641', # Office 2007 / Compatibility Pack / Excel Viewer
  '2817670', # Office 2010 / PowerPoint Viewer
  '2899397', # Lync 2010
  '2899393', # Lync 2010 Attendee (user level)
  '2899395', # Lync 2010 Attendee (admin level)
  '2850057'  # Lync 2013
);

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);
vuln = FALSE;

# Connect to the registry
userpaths = get_user_dirs();
arch = get_kb_item_or_exit("SMB/ARCH", exit_code:1);
if (arch == "x64")
  extra = "\Wow6432Node";
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);


# Microsoft Lync 2010
lync2010_path = get_registry_value(
  handle : hklm,
  item   : 'SOFTWARE'+extra+'\\Microsoft\\Communicator\\InstallationDirectory'
);

# Microsoft Lync 2010 Attendee (admin level install)
lync2010_att_admin_path = get_registry_value(
  handle : hklm,
  item   : 'SOFTWARE\\Microsoft\\AttendeeCommunicator\\InstallationDirectory'
);

# Microsoft Lync Basic 2013
lync2013_path = get_registry_value(
  handle : hklm,
  item   : 'Software\\Microsoft\\Office\\15.0\\Lync\\InstallationDirectory'
);

# Microsoft Visual Studio .NET 2003
vs2003_path = get_registry_value(
  handle : hklm,
  item   : 'Software\\Microsoft\\VisualStudio\\7.1\\InstallDir'
);

# Close connection to registry
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

# Lync 2010 #
if (lync2010_path)
{
  check_vuln(
    name    : 'Microsoft Lync 2010',
    kb      : "2899397",
    path    : lync2010_path + "\communicator.exe",
    min_ver : "4.0.0.0",
    fix     : "4.0.7577.4415"
  );
}

# Lync Attendee Admin Level Install #
if (lync2010_att_admin_path)
{
  check_vuln(
    name    : 'Microsoft Lync 2010 Attendee (admin level install)',
    kb      : "2899395",
    path    : lync2010_att_admin_path + "\MeetingJoinAxAOC.DLL",
    min_ver : "4.0.0.0",
    fix     : "4.0.7577.4415"
  );
}

# Lync 2010 Attendee User Level Install #
foreach userdir (keys(userpaths))
{
  check_vuln(
    name    : 'Microsoft Lync 2010 Attendee (user level install)',
    kb      : "2899393",
    path    : userdir + "\Microsoft Lync Attendee\MeetingJoinAxAOC.DLL",
    min_ver : "4.0.0.0",
    fix     : "4.0.7577.4415"
  );
}

# Lync 2013 #
if (lync2013_path)
{
  check_vuln(
    name    : 'Microsoft Lync 2013',
    kb      : "2850057",
    path    : lync2013_path + "\Lync.exe",
    min_ver : "15.0.0.0",
    fix     : "15.0.4551.1007"
  );
}

office_versions = hotfix_check_office_version();
# Office 2003 SP3 #
if (office_versions["11.0"])
{
  office_sp = get_kb_item("SMB/Office/2003/SP");
  if (office_sp == 3)
  {
    path = hotfix_get_officeprogramfilesdir(officever:"11.0") + "\Microsoft Office\OFFICE11";

    if (
      hotfix_is_vulnerable(file:"Gdiplus.dll", version:"11.0.8408.0", min_version:"11.0.0.0", path:path, bulletin:bulletin, kb:'2850047')
    )
    {
      vuln++;
    }
    NetUseDel(close:FALSE);
  }
}

commonfiles = hotfix_get_commonfilesdir();
# Office 2007 SP3 #
if (office_versions["12.0"])
{
  office_sp = get_kb_item("SMB/Office/2007/SP");
  if (office_sp == 3)
  {
    if (
      commonfiles &&
      hotfix_is_vulnerable(file:"Ogl.dll", version:"12.0.6688.5000", min_version:"12.0.0.0", path:commonfiles + "\Microsoft Shared\Office12", bulletin:bulletin, kb:'2817641')
    )
    {
      vuln++;
    }
    NetUseDel(close:FALSE);
  }
}

# Office 2010 SP1 #
if (office_versions["14.0"])
{
  office_sp = get_kb_item("SMB/Office/2010/SP");
  if (office_sp == 1 || office_sp == 2)
  {
    if (
      commonfiles &&
      hotfix_is_vulnerable(file:"Ogl.dll", version:"14.0.7110.5004", min_version:"14.0.0.0", path:commonfiles + "\Microsoft Shared\OFFICE14", bulletin:bulletin, kb:'2817670')
    )
    {
      vuln++;
    }
    NetUseDel(close:FALSE);
  }
}

systemroot = hotfix_get_systemroot();

# Vista
# Server 2008
if (
  hotfix_check_sp_range(vista:'2') > 0
)
{
  kb = '2901674';
  login   =  kb_smb_login();
  pass    =  kb_smb_password();
  domain  =  kb_smb_domain();
  winsxs = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\WinSxS", string:systemroot);
  winsxs_share = hotfix_path2share(path:systemroot);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:winsxs_share);
  if (rc != 1)
    NetUseDel(close:FALSE);

  files = list_dir(basedir:winsxs, level:0, dir_pat:"microsoft.windows.gdiplus", file_pat:"^gdiplus\.dll$", max_recurse:1);

  vuln += hotfix_check_winsxs(os:'6.0', sp:2, files:files, versions:make_list('6.0.6002.18971', '6.0.6002.23256'), max_versions:make_list('6.0.6002.20000', '6.0.6002.99999'), bulletin:bulletin, kb:kb);
}

if (vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
