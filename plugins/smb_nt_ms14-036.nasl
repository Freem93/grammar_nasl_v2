#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74428);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2014-1817", "CVE-2014-1818");
  script_bugtraq_id(67897, 67904);
  script_osvdb_id(107830, 107831);
  script_xref(name:"MSFT", value:"MS14-036");
  script_xref(name:"IAVA", value:"2014-A-0080");

  script_name(english:"MS14-036: Vulnerabilities in Microsoft Graphics Component Could Allow Remote Code Execution (2967487)");
  script_summary(english:"Checks file versions");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple remote code execution
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft's Graphics Component installed on the remote
host is affected by code execution vulnerabilities due to the way GDI+
handles image record types in specially crafted files. A remote,
unauthenticated attacker could exploit these issues by tricking a user
into viewing content that contains malicious files, which could result
in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms14-036");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Server 2003,
Vista, Server 2008, 7, 2008 R2, 8, 8.1, 2012, 2012 R2, Office 2007,
Office 2010, Live Meeting 2007 Console, Lync 2010, Lync 2010 Attendee,
Lync 2013, and Lync Basic 2013.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:live_meeting_console");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync_attendee");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync_basic");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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
bulletin = 'MS14-036';
kbs = make_list(
  2957503,
  2957509,
  2964736,
  2965155,
  2964718,
  2878233,
  2881069,
  2863942,
# 2767915, # replaced by KB 2881071 on 12 AUG 2014
  2881071,
  2963285,
  2963282,
  2963284,
  2881013,
  2965161,
  2968966
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Uninstall/Enumerated", exit_code:1);
vuln = 0;

commonfiles = hotfix_get_commonfilesdir();
if (!commonfiles) audit(AUDIT_PATH_NOT_DETERMINED, 'Common Files');
systemroot = hotfix_get_systemroot();
if (!systemroot) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');

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

# Live Meeting 2007 Console
list = get_kb_list_or_exit("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
foreach key (keys(list))
{
  if ('Microsoft Office Live Meeting 2007' >< list[key])
  {
    key = str_replace(string:key, find:"/DisplayName", replace:"/InstallLocation");
    key = key - "SMB/Registry/HKLM/";
    key = str_replace(string:key, find:"/", replace:'\\');
    live_meeting_2007_path = get_registry_value(
      handle : hklm,
      item   : key
    );
  }
}

# Close connection to registry
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

# Live Meeting 2007 Console
if (live_meeting_2007_path)
{
  check_vuln(
    name    : 'Live Meeting 2007 Console',
    kb      : '2968966',
    path    : live_meeting_2007_path + "\pubutil.dll",
    min_ver : "8.0.0.0",
    fix     : "8.0.6362.223"
  );
}

# Lync 2010 #
if (lync2010_path)
{
  check_vuln(
    name    : 'Microsoft Lync 2010',
    kb      : "2963285",
    path    : lync2010_path + "\communicator.exe",
    min_ver : "4.0.0.0",
    fix     : "4.0.7577.4446"
  );
}

# Lync Attendee Admin Level Install #
if (lync2010_att_admin_path)
{
  check_vuln(
    name    : 'Microsoft Lync 2010 Attendee (admin level install)',
    kb      : "2963284",
    path    : lync2010_att_admin_path + "\MeetingJoinAxAOC.DLL",
    min_ver : "4.0.0.0",
    fix     : "4.0.7577.4446"
  );
}

# Lync 2010 Attendee User Level Install #
foreach userdir (keys(userpaths))
{
  check_vuln(
    name    : 'Microsoft Lync 2010 Attendee (user level install)',
    kb      : "2963282",
    path    : userdir + "\Microsoft Lync Attendee\MeetingJoinAxAOC.DLL",
    min_ver : "4.0.0.0",
    fix     : "4.0.7577.4446"
  );
}

# Lync 2013 / 2013 SP1 #
if (lync2013_path)
{
  check_vuln(
    name    : 'Microsoft Lync 2013',
    kb      : "2881013",
    path    : lync2013_path + "\Lync.exe",
    min_ver : "15.0.0.0",
    fix     : "15.0.4623.1000"
  );
}

office_versions = hotfix_check_office_version();
# Office 2007 SP3 #
if (office_versions["12.0"])
{
  office_sp = get_kb_item("SMB/Office/2007/SP");
  if (office_sp == 3)
  {
    if (
      hotfix_is_vulnerable(product:"Office 2007", file:"Ogl.dll", version:"12.0.6700.5000", min_version:"12.0.0.0", path:commonfiles + "\Microsoft Shared\Office12", bulletin:bulletin, kb:'2878233') ||
      hotfix_is_vulnerable(product:"Office 2007", file:"Usp10.dll", version:"1.626.6002.23386", min_version:"1.626.6002.0", path:commonfiles + "\Microsoft Shared\Office12", bulletin:bulletin, kb:'2881069')
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
    path = '';
    paths = get_kb_list("SMB/Office/*/14.0/Path");
    if (!isnull(paths))
    {
      paths = list_uniq(make_list(paths));
      path = paths[0];
    }

    # Make sure that installed office version is targeted by KB 2767915.
    # Note that KB 2767915 is replaced by KB 2881071 on 12 AUG 2014
    office_code = get_kb_item("SMB/Office/2010/IdentifyingNumber");
    usp10_affected_list = "90140000-001C-0000-1000-0000000FF1CE, 91140000-0015-0000-1000-0000000FF1CE, 90140000-0015-0000-1000-0000000FF1CE, 91140000-0013-0000-1000-0000000FF1CE, 91140000-0016-0000-1000-0000000FF1CE, 90140000-0016-0000-1000-0000000FF1CE, 91140000-00BA-0000-1000-0000000FF1CE, 90140000-00BA-0000-1000-0000000FF1CE, 91140000-0044-0000-1000-0000000FF1CE, 90140000-0044-0000-1000-0000000FF1CE, 91140000-00A1-0000-1000-0000000FF1CE, 90140000-00A1-0000-1000-0000000FF1CE, 91140000-001A-0000-1000-0000000FF1CE, 90140000-001A-0000-1000-0000000FF1CE, 91140000-0033-0000-1000-0000000FF1CE, 91140000-0018-0000-1000-0000000FF1CE, 90140000-0018-0000-1000-0000000FF1CE, 91140000-003B-0000-1000-0000000FF1CE, 90140000-003B-0000-1000-0000000FF1CE, 91140000-003A-0000-1000-0000000FF1CE, 90140000-003A-0000-1000-0000000FF1CE, 91140000-0011-0000-1000-0000000FF1CE, 91140000-011D-0000-1000-0000000FF1CE, 90140000-0011-0000-1000-0000000FF1CE, 91140000-0014-0000-1000-0000000FF1CE, 91140000-0019-0000-1000-0000000FF1CE, 90140000-0019-0000-1000-0000000FF1CE, 90140000-0017-0000-1000-0000000FF1CE, 90140000-003D-0000-1000-0000000FF1CE, 91140000-008B-0000-1000-0000000FF1CE, 90140000-008B-0000-1000-0000000FF1CE";
    if (!isnull(office_code) && office_code >< usp10_affected_list) usp10_target = TRUE;
    else usp10_target = FALSE;

    if (
      hotfix_is_vulnerable(product:"Office 2010", file:"Ogl.dll", version:"14.0.7125.5000", min_version:"14.0.0.0", path:commonfiles + "\Microsoft Shared\Office14", bulletin:bulletin, kb:'2863942') ||
      (usp10_target && path && hotfix_is_vulnerable(product:"Office 2010", file:"Usp10.dll", version:"1.626.7601.22666", min_version:"1.626.7601.0", path:commonfiles + "\Microsoft Shared\Office14", bulletin:bulletin, kb:'2881071'))
      ||
      # Perhaps 2767915 (old and replaced) is installed and 2881071 (new) is NOT installed.
      # MS says 2881071 is needed in this case ... even if file vers are the same.
      (
        get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Updates/KB2767915")
        &&
        !get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Updates/KB2881071")
      )
    )
    {
      vuln++;
    }
    NetUseDel(close:FALSE);
  }
}

if (
  hotfix_check_sp_range(win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') > 0
)
{
  if (
    # Windows 8.1 / 2012 R2
    hotfix_is_vulnerable(os:"6.3", sp:0, file:"Fntcache.dll", version:"6.3.9600.17111", min_version:"6.3.9600.17000", dir:"system32", bulletin:bulletin, kb:"2964718") ||
    hotfix_is_vulnerable(os:"6.3", sp:0, file:"Fntcache.dll", version:"6.3.9600.16662", min_version:"6.3.9600.16000", dir:"system32", bulletin:bulletin, kb:"2965161") ||
    hotfix_is_vulnerable(os:"6.3", sp:0, file:"gdi32.dll", version:"6.3.9600.17111", min_version:"6.3.9600.17000", dir:"system32", bulletin:bulletin, kb:"2964736") ||
    hotfix_is_vulnerable(os:"6.3", sp:0, file:"gdi32.dll", version:"6.3.9600.16662", min_version:"6.3.9600.16000", dir:"system32", bulletin:bulletin, kb:"2965155") ||

    # Windows 8 / 2012
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"gdi32.dll", version:"6.2.9200.21032", min_version:"6.2.9200.20000", dir:"system32", bulletin:bulletin, kb:"2964736") ||
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"gdi32.dll", version:"6.2.9200.16909", min_version:"6.2.9200.16000", dir:"system32", bulletin:bulletin, kb:"2964736") ||

    # Windows 7 / 2008 R2
    hotfix_is_vulnerable(os:'6.1', sp:1, arch:"x64", file:"Usp10.dll", version:"1.626.7601.22666", min_version:"1.626.7601.22000", dir:"\SysWOW64", bulletin:bulletin, kb:"2957509") ||
    hotfix_is_vulnerable(os:'6.1', sp:1, arch:"x64", file:"Usp10.dll", version:"1.626.7601.18454", min_version:"1.626.7600.18000", dir:"\SysWOW64", bulletin:bulletin, kb:"2957509") ||
    hotfix_is_vulnerable(os:'6.1', sp:1,             file:"Usp10.dll", version:"1.626.7601.22666", min_version:"1.626.7601.22000", dir:"\system32", bulletin:bulletin, kb:"2957509") ||
    hotfix_is_vulnerable(os:'6.1', sp:1,             file:"Usp10.dll", version:"1.626.7601.18454", min_version:"1.626.7600.18000", dir:"\system32", bulletin:bulletin, kb:"2957509") ||


    # Vista / Server 2008
    hotfix_is_vulnerable(os:'6.0', sp:2, arch:"x64", file:"Usp10.dll", version:"1.626.6002.23386", min_version:"1.626.6002.22000", dir:"\SysWOW64", bulletin:bulletin, kb:"2957509") ||
    hotfix_is_vulnerable(os:'6.0', sp:2, arch:"x64", file:"Usp10.dll", version:"1.626.6002.19096", min_version:"1.626.6002.18000", dir:"\SysWOW64", bulletin:bulletin, kb:"2957509") ||
    hotfix_is_vulnerable(os:'6.0', sp:2,             file:"Usp10.dll", version:"1.626.6002.23386", min_version:"1.626.6002.22000", dir:"\system32", bulletin:bulletin, kb:"2957509") ||
    hotfix_is_vulnerable(os:'6.0', sp:2,             file:"Usp10.dll", version:"1.626.6002.19096", min_version:"1.626.6002.18000", dir:"\system32", bulletin:bulletin, kb:"2957509") ||

    # Server 2003
    hotfix_is_vulnerable(os:'5.2', sp:2, arch:"x64", file:"Usp10.dll", version:"1.422.3790.5340",                                  dir:"\SysWOW64", bulletin:bulletin, kb:'2957509') ||
    hotfix_is_vulnerable(os:'5.2', sp:2, arch:"x86", file:"Usp10.dll", version:"1.422.3790.5340",                                  dir:"\system32", bulletin:bulletin, kb:'2957509')
  ) vuln++;

  login  = kb_smb_login();
  pass   = kb_smb_password();
  domain = kb_smb_domain();

  # GDI+ Check
  winsxs = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\WinSxS", string:systemroot);
  winsxs_share = hotfix_path2share(path:systemroot);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:winsxs_share);
  if (rc != 1)
    NetUseDel(close:FALSE);

  files = list_dir(basedir:winsxs, level:0, dir_pat:"microsoft.windows.gdiplus", file_pat:"^gdiplus\.dll$", max_recurse:1);
  vuln += hotfix_check_winsxs(os:'6.1', sp:1, files:files, versions:make_list('5.2.7601.18455', '5.2.7601.22667', '6.1.7601.18445', '6.1.7601.22667'), max_versions:make_list('5.2.7601.20000', '5.2.7601.99999', '6.1.7601.20000', '6.1.7601.99999'), bulletin:bulletin, kb:"2957503");
  vuln += hotfix_check_winsxs(os:'6.0', sp:2, files:files, versions:make_list('5.2.6002.19096', '5.2.6002.23386', '6.0.6002.19096', '6.0.6002.23386'), max_versions:make_list('5.2.6002.19999', '5.2.6002.29999', '6.0.6002.19999', '6.0.6002.29999'), bulletin:bulletin, kb:"2957503");
  vuln += hotfix_check_winsxs(os:'5.2', sp:2, files:files, versions:make_list('5.2.6002.23386'), max_versions:make_list('5.2.6002.99999'), bulletin:bulletin, kb:"2957503");
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
