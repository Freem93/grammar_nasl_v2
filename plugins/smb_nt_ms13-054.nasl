#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67211);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/04/23 21:44:06 $");

  script_cve_id("CVE-2013-3129");
  script_bugtraq_id(60978);
  script_osvdb_id(94960);
  script_xref(name:"MSFT", value:"MS13-054");
  script_xref(name:"IAVA", value:"2013-A-0135");

  script_name(english:"MS13-054: Vulnerability in GDI+ Could Allow Remote Code Execution (2848295)");
  script_summary(english:"Authenticated check for outdated GDI+");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host has a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft's GDI+ subsystem installed on the remote host
has an unspecified code execution vulnerability. Specially crafted
TrueType font files are not processed properly. A remote,
unauthenticated attacker could exploit this vulnerability by getting a
user to view content that contains malicious TrueType font files,
resulting in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-054");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows, Office 2003,
Office 2007, Office 2010, Lync 2010, Lync 2010 Attendee, Lync 2013,
and Lync Basic 2013.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

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
  if (is_accessible_share(share:share))
    return TRUE;

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
  '2687276', # Office 2010 SP1
  '2687309', # Office 2007 SP3
  '2817465', # Lync 2013
  '2817480', # Office 2003 SP3
  '2834886', # Windows GDI+
  '2835361', # DirectWrite (Windows)
  '2835364', # Windows Journal
  '2843160', # Lync 2010
  '2843162', # Lync 2013 Attendee (user level install)
  '2843163', # Lync 2013 Attendee (admin level install)
  '2856545'  # Visual Studio .NET 2003
);

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

systemroot = hotfix_get_systemroot();
if (!systemroot) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');
commonfiles = hotfix_get_commonfilesdir();
if (!commonfiles) audit(AUDIT_PATH_NOT_DETERMINED, 'Common Files');
winsxs = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\WinSxS", string:systemroot);
winsxs_share = hotfix_path2share(path:systemroot);

port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

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

if (lync2010_path)
{
  check_vuln(
    name    : 'Microsoft Lync 2010',
    kb      : "2843160",
    path    : lync2010_path + "\communicator.exe",
    min_ver : "4.0.0.0",
    fix     : "4.0.7577.4392"
  );
}

if (lync2010_att_admin_path)
{
  check_vuln(
    name    : 'Microsoft Lync 2010 Attendee (admin level install)',
    kb      : "2843163",
    path    : lync2010_att_admin_path + "\MeetingJoinAxAOC.DLL",
    min_ver : "4.0.0.0",
    fix     : "4.0.7577.4392"
  );
}

foreach userdir (keys(userpaths))
{
  check_vuln(
    name    : 'Microsoft Lync 2010 Attendee (user level install)',
    kb      : "2843162",
    path    : userdir + "\Microsoft Lync Attendee\MeetingJoinAxAOC.DLL",
    min_ver : "4.0.0.0",
    fix     : "4.0.7577.4392"
  );
}

if (lync2013_path)
{
  check_vuln(
    name    : 'Microsoft Lync 2013',
    kb      : "2817465",
    path    : lync2013_path + "\Lync.exe",
    min_ver : "15.0.0.0",
    fix     : "15.0.4517.1004"
  );
}

if (vs2003_path)
{
  msoxp_path = commonfiles + "\Microsoft Shared\Office10";

  check_vuln(
    name    : 'Microsoft Visual Studio .NET 2003',
    kb      : "2856545",
    path    : msoxp_path + "\mso.dll",
    min_ver : "10.0.0.0",
    fix     : "10.0.6885.0"
  );
}

office_versions = hotfix_check_office_version();

# Office 2003 SP3
if (office_versions["11.0"])
{
  office_sp = get_kb_item("SMB/Office/2003/SP");
  if (office_sp == 3)
  {
    path = hotfix_get_officeprogramfilesdir(officever:"11.0") + "\Microsoft Office\OFFICE11";

    if (
      hotfix_is_vulnerable(file:"Gdiplus.dll", version:"11.0.8404.0", min_version:"11.0.0.0", path:path, bulletin:bulletin, kb:'2817480')
    )
    {
      vuln++;
    }
    NetUseDel(close:FALSE);
  }
}

# Office 2007 SP3
if (office_versions["12.0"])
{
  office_sp = get_kb_item("SMB/Office/2007/SP");
  if (office_sp == 3)
  {
    path = commonfiles + "\Microsoft Shared\OFFICE12";

    if (hotfix_is_vulnerable(file:"Ogl.dll", version:"12.0.6679.5000", min_version:"12.0.0.0", path:path, bulletin:bulletin, kb:'2687309'))
    {
      vuln++;
    }
    NetUseDel(close:FALSE);
  }
}

# Office 2010 SP1
if (office_versions["14.0"])
{
  office_sp = get_kb_item("SMB/Office/2010/SP");
  if (office_sp == 1)
  {
    path = commonfiles + "\Microsoft Shared\OFFICE14";

    if (path && hotfix_is_vulnerable(file:"Ogl.dll", version:"14.0.7102.5000", min_version:"14.0.0.0", path:path, bulletin:bulletin, kb:'2687276'))
    {
      vuln++;
    }
    NetUseDel(close:FALSE);
  }
}

# the updates for Journal and DirectWrite are only applicable for:
#
# Vista
# Server 2008
# 7
# Server 2008 R2
# 8
# Server 2012
#
# the Journal update does also apply to Windows XP Tablet PC Edition 2005 but
# we don't support authenticated scans for that version of Windows
if (
  hotfix_check_sp_range(vista:'2', win7:'1', win8:'0') > 0
)
{
  # Windows Journal
  kb = '2835364';
  journal_path = commonfiles + "\microsoft shared\ink";
  if (
    hotfix_check_server_core() != 1 && # server core is not affected
    (
      # Windows 8 / Windows Server 2012
      hotfix_is_vulnerable(os:"6.2", arch:"x86", sp:0, file:"Journal.dll", version:"6.2.9200.16581", min_version:"6.2.9200.16000", path:journal_path, bulletin:bulletin, kb:kb) ||
      hotfix_is_vulnerable(os:"6.2", arch:"x86", sp:0, file:"Journal.dll", version:"6.2.9200.20685", min_version:"6.2.9200.20000", path:journal_path, bulletin:bulletin, kb:kb) ||
      hotfix_is_vulnerable(os:"6.2", arch:"x64", sp:0, file:"Journal.dll", version:"6.2.9200.16579", min_version:"6.2.9200.16000", path:journal_path, bulletin:bulletin, kb:kb) ||
      hotfix_is_vulnerable(os:"6.2", arch:"x64", sp:0, file:"Journal.dll", version:"6.2.9200.20682", min_version:"6.2.9200.20000", path:journal_path, bulletin:bulletin, kb:kb) ||

      # Windows 7 and Windows Server 2008 R2
      hotfix_is_vulnerable(os:"6.1", sp:1, file:"Journal.dll", version:"6.1.7601.22296", min_version:"6.1.7601.22000", path:journal_path, bulletin:bulletin, kb:kb) ||
      hotfix_is_vulnerable(os:"6.1", sp:1, file:"Journal.dll", version:"6.1.7601.18126", min_version:"6.1.7600.18000", path:journal_path, bulletin:bulletin, kb:kb) ||

      # Vista / Windows 2008
      hotfix_is_vulnerable(os:"6.0", sp:2, file:"Journal.dll", version:"6.0.6002.23094", min_version:"6.0.6002.20000", path:journal_path, bulletin:bulletin, kb:kb) ||
      hotfix_is_vulnerable(os:"6.0", sp:2, file:"Journal.dll", version:"6.0.6002.18817", min_version:"6.0.6002.18000", path:journal_path, bulletin:bulletin, kb:kb)
    )
  )
  {
     vuln ++;
  }
}

rc = NetUseAdd(login:login, password:pass, domain:domain, share:winsxs_share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, winsxs_share);
}

# DirectWrite
if (
  hotfix_check_sp_range(vista:'2', win7:'1', win8:'0') > 0 &&
  (hotfix_check_server_core() != 1 || hotfix_check_sp_range(win8:'0') > 0) # server core is only affected for Server 2012
)
{
  kb = '2835361';
  files = list_dir(basedir:winsxs, level:0, dir_pat:"microsoft-windows-directwrite", file_pat:"^[Dd][Ww]rite\.dll$");

  # Windows 8 / Windows Server 2012
  vuln += hotfix_check_winsxs(os:'6.2', sp:0, arch:'x86', files:files, versions:make_list('6.2.9200.16581', '6.2.9200.20685'),
                              max_versions:make_list('6.2.9200.20000', '6.2.9200.99999'), bulletin:bulletin, kb:kb);
  vuln += hotfix_check_winsxs(os:'6.2', sp:0, arch:'x64', files:files, versions:make_list('6.2.9200.16579', '6.2.9200.20682'),
                              max_versions:make_list('6.2.9200.20000', '6.2.9200.99999'), bulletin:bulletin, kb:kb);

  # Windows 7 and Windows Server 2008 R2
  vuln += hotfix_check_winsxs(os:'6.1', sp:1, files:files,
                              versions:make_list('6.1.7601.18126', '6.1.7601.22296', '6.2.9200.16571', '6.2.9200.20675'),
                              max_versions:make_list('6.1.7601.22000', '6.1.7601.99999', '6.2.9200.20000', '6.2.9200.99999'),
                              bulletin:bulletin, kb:kb);

  # Vista / Windows 2008
  vuln += hotfix_check_winsxs(os:'6.0', sp:2, files:files, versions:make_list('7.0.6002.18827', '7.0.6002.23097'),
                              max_versions:make_list('7.0.6002.20000', '7.0.6002.99999'), bulletin:bulletin, kb:kb);
}


# the updates for Journal and DirectWrite are only applicable for:
#
# XP
# Server 2003
# Vista
# Server 2008
# 7
# Server 2008 R2
#
# the server core editions of 2008 and 2008 R2 are both affected
if (
  hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'1') > 0
)
{
  kb = '2834886';
  files = list_dir(basedir:winsxs, level:0, dir_pat:"microsoft.windows.gdiplus", file_pat:"^gdiplus\.dll$", max_recurse:1);

  vuln += hotfix_check_winsxs(os:'5.1', sp:3, files:files, versions:make_list('5.2.6002.23084'), bulletin:bulletin, kb:kb);
  vuln += hotfix_check_winsxs(os:'5.2', sp:2, files:files, versions:make_list('5.2.6002.23084'), bulletin:bulletin, kb:kb);
  vuln += hotfix_check_winsxs(os:'6.0', sp:2, files:files, versions:make_list('6.0.6002.18813', '6.0.6002.23084'), max_versions:make_list('6.0.6002.20000', '6.0.6002.99999'), bulletin:bulletin, kb:kb);
  versions = make_list('5.2.7601.18120', '5.2.7601.22290', '6.1.7601.18120', '6.1.7601.22290');
  max_versions = make_list('5.2.7601.20000', '5.2.7601.99999', '6.1.7601.20000', '6.1.7601.99999');
  vuln += hotfix_check_winsxs(os:'6.1', sp:1, files:files, versions:versions, max_versions:max_versions, bulletin:bulletin, kb:kb);
}

hotfix_check_fversion_end();

if (!vuln)
  audit(AUDIT_HOST_NOT, 'affected');

# Flag the system as vulnerable
set_kb_item(name:"SMB/Missing/" + bulletin, value:TRUE);
hotfix_security_hole();
