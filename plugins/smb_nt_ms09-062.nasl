#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42118);
  script_version("$Revision: 1.37 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id(
    "CVE-2009-2500",
    "CVE-2009-2501",
    "CVE-2009-2502",
    "CVE-2009-2503",
    "CVE-2009-2504",
    "CVE-2009-2518",
    "CVE-2009-2528",
    "CVE-2009-3126"
  );
  script_bugtraq_id(
    36619,
    36645,
    36646,
    36647,
    36648,
    36649,
    36650,
    36651
  );
  script_osvdb_id(
    58863,
    58864,
    58865,
    58866,
    58867,
    58868,
    58869,
    58870
  );
  script_xref(name:"IAVA", value:"2009-A-0099");
  script_xref(name:"MSFT", value:"MS09-062");

  script_name(english:"MS09-062: Vulnerabilities in GDI+ Could Allow Remote Code Execution (957488)");
  script_summary(english:"Checks the version of gdiplus.exe");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the
Microsoft GDI rendering engine.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows that is affected by
multiple buffer overflow vulnerabilities when viewing TIFF, PNG, BMP,
and Office files that could allow an attacker to execute arbitrary
code on the remote host. Additionally, there is a GDI+ .NET API
vulnerability that allows a malicious .NET application to gain
unmanaged code execution privileges.

To exploit these flaws, an attacker would need to send a malformed
image file to a user on the remote host and wait for them to open it
using an affected Microsoft application.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-062");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, IE, .NET Framework, Office, SQL Server, Developer Tools, and
Forefront.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(94, 119, 189);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visio");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:works");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "mssql_version.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}


include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS09-062';
kbs = make_list("958869", "970894", "970899", "971022", "971023", "971104", "972221", "972580", "972581", "974811", "975365");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'2,3', win2003:'2', vista:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();
port    =  kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

hcf_init = TRUE;

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = 0;
path = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:rootfile);
office_versions = hotfix_check_office_version ();
office_sp = get_kb_item("SMB/Office/SP");
ver_list = get_kb_list("mssql/installs/*/SQLVersion");
visiopaths = get_kb_item("SMB/Office/Visio/*/VisioPath");
progfiles = hotfix_get_programfilesdir();
cdir = hotfix_get_commonfilesdir();

# Look in the registry for install info on a few of the apps being tested
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

# Detect Visual Studio 2005 installs
key = "SOFTWARE\Microsoft\VisualStudio\8.0";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallDir");
  if (!isnull(item))
  {
    vs2005_path = item[1];
    vs2005_root = ereg_replace(
      pattern:"^(.+)\\Common7\\IDE\\$", replace:"\1", string:vs2005_path,
      icase:TRUE
    );
  }

  RegCloseKey(handle:key_h);
}

# Detect Visual FoxPro installs
vfp8key = "SOFTWARE\Microsoft\VisualFoxPro\8.0\Setup\VFP";
vfp8key_h = RegOpenKey(handle:hklm, key:vfp8key, mode:MAXIMUM_ALLOWED);
if (!isnull(vfp8key_h))
{
  item = RegQueryValue(handle:vfp8key_h, item:"ProductDir");
  if (!isnull(item)) vfp8_path = item[1];

  RegCloseKey(handle:vfp8key_h);
}

vfp9key = "SOFTWARE\Microsoft\VisualFoxPro\9.0\Setup\VFP";
vfp9key_h = RegOpenKey(handle:hklm, key:vfp9key, mode:MAXIMUM_ALLOWED);
if (!isnull(vfp9key_h))
{
  item = RegQueryValue(handle:vfp9key_h, item:"ProductDir");
  if (!isnull(item)) vfp9_path = item[1];

  RegCloseKey(handle:vfp9key_h);
}

RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 )
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}


# IE 6 on Windows 2000 SP4 (KB958869)
if (hotfix_is_vulnerable(os:"5.0", file:"Vgx.dll", version:"6.0.2800.1637", min_version:"6.0.0.0", dir:"\Microsoft Shared\VGX", path:cdir, bulletin:bulletin, kb:'958869'))
{
  vuln++;
}

# Visio 2002 (KB975365)
if (!isnull(visiopaths))
{
  foreach visiopath (keys(visiopaths))
  {
    if ("10.0" >< visiopath)
    {
      if (hotfix_is_vulnerable(file:"visio.exe", version:"10.0.6885.4", min_version:"10.0.0.0", path:visiopath, dir:"\Visio10", bulletin:bulletin, kb:'975365'))
        vuln++;
    }
  }
}

msoxp_path = cdir + "\Microsoft Shared\Office10";

# The fixes for Office XP SP3 and Visual Studio.NET SP1 both update the same
# exact file.  The Office fix supersedes the VS .NET fix.
if (office_versions["10.0"])
{
  office_sp = get_kb_item("SMB/Office/XP/SP");
  if (!isnull(office_sp) && office_sp == 3)
  {
    # Office XP SP3 (KB974811)
    if(hotfix_is_vulnerable(file:"mso.dll", version:"10.0.6856.0", path:msoxp_path, bulletin:bulletin, kb:'974811'))
    {
      vuln++;
    }
  }
}
else
{
  # Visual Studio .NET 2003 SP1 (KB971022).  The 'min_version' arg is used to
  # prevent from firing on Office XP < SP3
  if(hotfix_is_vulnerable(file:"mso.dll", version:"10.0.6855.0",   min_version:"10.0.6802.0", path:msoxp_path, bulletin:bulletin, kb:'971022'))
  {
    vuln++;
  }
}

# Office 2003 SP3 (KB972580)
if (office_versions["11.0"])
{
  office_sp = get_kb_item("SMB/Office/2003/SP");
  if (!isnull(office_sp) && office_sp == 3)
  {
    path = hotfix_get_officeprogramfilesdir(officever:"11.0") + "\Microsoft Office\OFFICE11";

    if (hotfix_is_vulnerable(file:"Gdiplus.dll", version:"11.0.8312.0",       min_version:"11.0.0.0", path:path, bulletin:bulletin, kb:'972580'))
    {
      vuln++;
    }
  }
}

# Office 2007 SP1 and SP2 (KB972581)
if (office_versions["12.0"])
{
  office_sp = get_kb_item("SMB/Office/2007/SP");
  if (!isnull(office_sp) && (office_sp == 1 || office_sp == 2))
  {
    path = hotfix_get_commonfilesdir() + "\Microsoft Shared\OFFICE12";

    if (hotfix_is_vulnerable(file:"Ogl.dll", version:"12.0.6509.5000", path:path, bulletin:bulletin, kb:'972581'))
    {
      vuln++;
    }
  }
}

# Visual FoxPro and the .NET Framework are only vulnerable on Windows 2000
if (hotfix_check_sp(win2k:6) > 0)
{
  if (
    # Visual FoxPro 8.0 SP1 (KB971104)
    hotfix_is_vulnerable(path:vfp8_path, file:"gdiplus.dll", version:"5.2.6001.22319", bulletin:bulletin, kb:'971104') ||

    # Visual FoxPro 9.0 SP2 (KB971105)
    hotfix_is_vulnerable(path:vfp9_path, file:"gdiplus.dll", version:"5.2.6001.22319", bulletin:bulletin, kb:'971105') ||

    # .NET Framework 1.1 SP1 (KB971108)
    hotfix_is_vulnerable(dir:"\Microsoft.Net\Framework\v1.1.4322", file:"gdiplus.dll", version:"5.2.6001.22319", min_version:"5.1.3102.1360", bulletin:bulletin, kb:'971108') ||

    # .NET Framework 2.0 SP1 (KB971110) and SP2 (KB971111)
    hotfix_is_vulnerable(dir:"\Microsoft.Net\Framework\v2.0.50727", file:"gdiplus.dll", version:"5.2.6001.22319", min_version:"5.1.3102.1355", bulletin:bulletin, kb:'971110')
  )
  {
    vuln++;
  }
}

# Visual Studio 2005 SP1 (KB971023)
if (vs2005_root)
{
  path = vs2005_root + '\\SDK\\v2.0\\BootStrapper\\Packages\\ReportViewer';

  if (hotfix_is_vulnerable(file:"reportviewer.exe", version:"2.0.50727.4401", min_version:"2.0.50727.0", path:path, bulletin:bulletin, kb:'971023'))
  {
    vuln++;
  }
}

# Visual Studio 2008
if (progfiles)
{
  path = progfiles + '\\Microsoft SDKs\\Windows\\v6.0A\\Bootstrapper\\Packages\\ReportViewer';

  if (
    # Visual Studio 2008 (KB972221)
    hotfix_is_vulnerable(file:"reportviewer.exe", version:"9.0.21022.227", min_version:"9.0.21022.0", path:path, bulletin:bulletin, kb:'972221') ||

    # Visual Studio 2008 SP1 (KB972222)
    hotfix_is_vulnerable(file:"reportviewer.exe", version:"9.0.30729.4402", min_version:"9.0.30729.0", path:path, bulletin:bulletin, kb:'972222')
  )
  {
    vuln++;
  }
}

foreach item (keys(ver_list))
{
  item -= 'mssql/installs/';
  item -= '/SQLVersion';
  sqlpath = item;

  share = hotfix_path2share(path:sqlpath);
  if (!is_accessible_share(share:share)) continue;

  version = get_kb_item("mssql/installs/" + sqlpath + "/SQLVersion");

  if(version !~ "^9\.00\.")
    continue;

  sqledition = get_kb_item("mssql/installs/" + sqlpath + "/edition_type");
  if(isnull(sqledition))
    sqledition = get_kb_item("mssql/installs/" + sqlpath + "/edition");

  # SQL server 2005 (excluding Express Edition)
  if (
    sqlpath &&
    sqledition && "Express" >!< sqledition && "Internal" >!< sqledition &&

    (
    # SP3 (KB970892 & KB970894)
    hotfix_is_vulnerable(path:sqlpath, file:"Sqlservr.exe", version:"2005.90.4262.0", min_version:"2005.90.4200.0", bulletin:bulletin, kb:'970894') ||
    hotfix_is_vulnerable(path:sqlpath, file:"Sqlservr.exe", version:"2005.90.4053.0", min_version:"2005.90.4000.0", bulletin:bulletin, kb:'970892') ||

    # SP2 (KB970895 & KB970896)
    hotfix_is_vulnerable(path:sqlpath, file:"Sqlservr.exe", version:"2005.90.3353.0", min_version:"2005.90.3200.0", bulletin:bulletin, kb:'970896') ||
    hotfix_is_vulnerable(path:sqlpath, file:"Sqlservr.exe", version:"2005.90.3080.0", min_version:"2005.90.3000.0", bulletin:bulletin, kb:'970895')
    )
  )
  {
    vuln++;
  }
}

foreach item (keys(ver_list))
{
  item -= 'mssql/installs/';
  item -= '/SQLVersion';
  sqlpath = item;

  share = hotfix_path2share(path:sqlpath);
  if (!is_accessible_share(share:share)) continue;

  version = get_kb_item("mssql/installs/" + sqlpath + "/SQLVersion");
  if(version !~ "^8\.")
    continue;

  # SQL server 2000 reporting services SP2 (KB970899)
  if (sqlpath)
  {
    sqlsrs_path = ereg_replace(
      pattern:"^(.*)\\Binn\\?",
      replace:"\1\Reporting Services\ReportServer\bin",
      string:sqlpath,
      icase:TRUE
    );
    if (hotfix_is_vulnerable(path:sqlsrs_path, file:"ReportingServicesLibrary.dll", version:"8.0.1067.0", bulletin:bulletin, kb:'970899'))
    {
      vuln++;
    }
  }
}

# If any of the above applications are vulnerable, there's no need to check
# the WinSxS dir (for the OS-specific patches
if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}

# KB958869.  Checks the SxS directory.  The bulletin says 2k, vista/2k8 SP2,
# and win7 aren't affected
if (hotfix_check_sp_range(xp:'2,3', win2003:'2', vista:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

vuln = 0;
kb = '958869';
winsxs = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\WinSxS", string:rootfile);
files = list_dir(basedir:winsxs, level:0, dir_pat:"microsoft.windows.gdiplus", file_pat:"^gdiplus\.dll$");

# Windows XP / Server 2003
vuln += hotfix_check_winsxs(os:'5.1', files:files, versions:make_list('5.2.6001.22319'), bulletin:bulletin, kb:kb);
vuln += hotfix_check_winsxs(os:'5.2', sp:2, files:files, versions:make_list('5.2.6001.22319'), bulletin:bulletin, kb:kb);

# Windows Vista / Server 2008
vuln += hotfix_check_winsxs(os:'6.0', files:files, versions:make_list('5.2.6001.22319'), max_versions:make_list('6.0.0.0'), bulletin:bulletin, kb:kb);
vuln += hotfix_check_winsxs(os:'6.0', sp:0, files:files, versions:make_list('6.0.6000.16782', '6.0.6000.20966'), max_versions:make_list('6.0.6000.20000', '6.0.6000.99999'), bulletin:bulletin, kb:kb);
vuln += hotfix_check_winsxs(os:'6.0', sp:1, files:files, versions:make_list('6.0.6001.18175', '6.0.6001.22319'), max_versions:make_list('6.0.6001.20000', '6.0.6001.99999'), bulletin:bulletin, kb:kb);

if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}

hotfix_check_fversion_end();
audit(AUDIT_HOST_NOT, 'affected');
