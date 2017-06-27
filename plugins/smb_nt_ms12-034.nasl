#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59042);
  script_version("$Revision: 1.45 $");
  script_cvs_date("$Date: 2017/02/13 20:45:10 $");

  script_cve_id(
    "CVE-2011-3402",
    "CVE-2012-0159",
    "CVE-2012-0162",
    "CVE-2012-0164",
    "CVE-2012-0165",
    "CVE-2012-0167",
    "CVE-2012-0176",
    "CVE-2012-0180",
    "CVE-2012-0181",
    "CVE-2012-1848"
  );
  script_bugtraq_id(
    50462,
    53324,
    53326,
    53327,
    53335,
    53347,
    53351,
    53358,
    53360,
    53363
  );
  script_osvdb_id(
    76843,
    81715,
    81716,
    81717,
    81718,
    81719,
    81720,
    81721,
    81722,
    81736
  );
  script_xref(name:"MSFT", value:"MS12-034");
  script_xref(name:"IAVA", value:"2012-A-0079");
  script_xref(name:"EDB-ID", value:"18894");
  script_xref(name:"ZDI", value:"ZDI-12-131");

  script_name(english:"MS12-034: Combined Security Update for Microsoft Office, Windows, .NET Framework, and Silverlight (2681578)");
  script_summary(english:"Checks the version of multiple files.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple vulnerabilities :

  - A flaw exists in the Win32k TrueType font parsing engine
    that allows an unauthenticated, remote attacker to
    execute arbitrary code by convincing a user to open a
    Word document containing malicious font data.
    (CVE-2011-3402)

  - A flaw exists in the t2embed.dll module when parsing
    TrueType fonts. An unauthenticated, remote attacker can
    exploit this, via a crafted TTF file, to execute
    arbitrary code. (CVE-2012-0159)

  - A flaw exists in the .NET Framework due to a buffer
    allocation error when handling an XBAP or .NET
    application. An unauthenticated, remote attacker can
    exploit this, via a specially crafted application, to
    execute arbitrary code. (CVE-2012-0162)

  - A flaw exists in the .NET Framework due to an error
    when comparing the value of an index in a WPF
    application. An unauthenticated, remote attacker can
    exploit this to cause a denial of service condition.
    (CVE-2012-0164)

  - An flaw exists in GDI+ when handling specially crafted
    EMF images that allows an unauthenticated, remote
    attacker to execute arbitrary code. (CVE-2012-0165)

  - A heap buffer overflow condition exists in Microsoft
    Office in the GDI+ library when handling EMF images
    embedded in an Office document. An unauthenticated,
    remote attacker can exploit this to execute arbitrary
    code by convincing a user to open a specially crafted
    document. (CVE-2012-0167)

  - A double-free error exists in agcore.dll when rendering
    XAML strings containing Hebrew Unicode glyphs of certain
    values. An unauthenticated, remote attacker can exploit
    this to execute arbitrary code by convincing a user to
    visit a specially crafted web page. (CVE-2012-0176)

  - A privilege escalation vulnerability exists in the
    way the Windows kernel-mode driver manages the functions
    related to Windows and Messages handling. A local
    attacker can exploit this, via a specially crafted
    application, to gain elevated privileges.
    (CVE-2012-0180)

  - A privilege escalation vulnerability exists in the way
    the Windows kernel-mode driver manages Keyboard Layout
    files. A local attacker can exploit this, via a
    specially crafted application, to gain elevated
    privileges. (CVE-2012-0181)

  - A privilege escalation vulnerability exists in the way
    the Windows kernel-mode driver manages scrollbar
    calculations. A local attacker can exploit this, via a
    specially crafted application, to gain elevated
    privileges. (CVE-2012-1848)");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-131/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Aug/60");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-034");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, 2008 R2; Office 2003, 2007, and 2010; .NET Framework 3.0,
3.5.1, and 4.0; and Silverlight 4 and 5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:silverlight");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies(
    "smb_hotfixes.nasl",
    "office_installed.nasl",
    "silverlight_detect.nasl",
    "ms_bulletin_checks_possible.nasl"
  );
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS12-034';
kbs = make_list(
  '2589337',
  '2596672',
  '2596672',
  '2596792',
  '2598253',
  '2636927',
  '2656405',
  '2656407',
  '2656409',
  '2656410',
  '2656411',
  '2658846',
  '2659262',
  '2660649',
  '2676562',
  '2686509',
  '2690729'
);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

vuln = 0;

#######################
# KB2686509           #
#######################
winver = get_kb_item('SMB/WindowsVersion');
spver = get_kb_item('SMB/CSDVersion');
prodname = get_kb_item('SMB/ProductName');
if (spver)
  spver = int(ereg_replace(string:spver, pattern:'.*Service Pack ([0-9]).*', replace:"\1"));
if (
  winver && spver && prodname &&
  ((winver == '5.2' && spver == 2) ||
  (winver == '5.1' && spver == 3))
)
{
  if (winver == '5.2' && spver == 2 && 'XP' >< prodname)
    reg_name = "SOFTWARE\Microsoft\Updates\Windows XP Version 2003\SP3\KB2686509\Description";
  else if (winver == '5.2' && spver == 2)
    reg_name = "SOFTWARE\Microsoft\Updates\Windows Server 2003\SP3\KB2686509\Description";
  else if (winver == '5.1' && spver == 3)
    reg_name = "SOFTWARE\Microsoft\Updates\Windows XP\SP4\KB2686509\Description";

  registry_init();
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  desc = get_registry_value(handle:hklm, item:reg_name);
  RegCloseKey(handle:hklm);
  close_registry();

  if (isnull(desc))
  {
    hotfix_add_report('  According to the registry, KB2686509 is missing.\n', bulletin:bulletin, kb:"2686509");
    vuln++;
  }
}

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
path  = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1$", string:rootfile);

login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();
port   = kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

hcf_init = TRUE;

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

office_versions = hotfix_check_office_version();
cdir = hotfix_get_commonfilesdir();

################################################################
# Office Checks                                                #
################################################################

#############################
# Office 2003 SP3 KB2598253 #
#############################
if (office_versions["11.0"])
{
  office_sp = get_kb_item("SMB/Office/2003/SP");
  if (!isnull(office_sp) && office_sp == 3)
  {
    path = hotfix_get_officeprogramfilesdir(officever:'11.0') + "\Microsoft Office\Office11";

    if (hotfix_is_vulnerable(file:"Gdiplus.dll", version:"11.0.8345.0", min_version:"11.0.0.0", path:path, bulletin:bulletin, kb:'2598253'))
      vuln++;
  }
}

#############################
# Office 2007 SP2           #
#   KB2596672, KB2596792    #
#############################
if (office_versions["12.0"])
{
  office_sp = get_kb_item("SMB/Office/2007/SP");
  if (!isnull(office_sp) && (office_sp == 2 || office_sp == 3))
  {
    path = cdir + "\Microsoft Shared\Office12";
    if (hotfix_is_vulnerable(file:"Ogl.dll", version:"12.0.6659.5000", path:path, bulletin:bulletin, kb:'2596672'))
      vuln++;

    path = cdir + "\Microsoft SHared\MODI\12.0";
    if (hotfix_is_vulnerable(file:"Mspcore.dll", version:"12.0.6658.5001", path:path, bulletin:bulletin, kb:'2596792'))
      vuln++;
  }
}

#############################
# Office 2010 KB2589337     #
#############################
if (office_versions["14.0"])
{
  office_sp = get_kb_item("SMB/Office/2010/SP");
  if (!isnull(office_sp) && (office_sp == 0 || office_sp == 1))
  {
    path = cdir + "\Microsoft Shared\Office14";
    if (hotfix_is_vulnerable(file:"Ogl.dll", version:"14.0.6117.5001", path:path, bulletin:bulletin, kb:'2589337'))
      vuln++;
  }
}

# Silverlight 4.x / 5.x
slfix = NULL;
slkb = NULL;
ver = get_kb_item("SMB/Silverlight/Version");
if (ver =~ '^4\\.' && ver_compare(ver:ver, fix:'4.1.10329.0') == -1)
{
  slfix = '4.1.10329';
  slkb = '2690729';
}
else if (ver =~ '^5\\.' && ver_compare(ver:ver, fix:'5.1.10411.0') == -1)
{
  slfix = '5.1.10411';
  slkb = '2636927';
}
if (slfix)
{
  path = get_kb_item("SMB/Silverlight/Path");
  report +=
    '\n  Product           : Microsoft Silverlight' +
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + slfix + '\n';
  hotfix_add_report(report, bulletin:bulletin, kb:slkb);
  vuln++;
}

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'0,1') <= 0)
{
  if (vuln > 0)
  {
    set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
    hotfix_security_hole();
    hotfix_check_fversion_end();
    exit(0);
  }
  else audit(AUDIT_OS_SP_NOT_VULN);
}

if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");
################################################################
# .NET Framework Checks                                        #
################################################################


net3path = hotfix_get_programfilesdir() + "\Reference Assemblies\Microsoft\Framework\v3.0";
if (!isnull(net3path))
{
  # .NET Framework 3.0 on Windows XP / Windows Server 2003
  missing = 0;
  missing += hotfix_is_vulnerable(os:"5.1", file:"PresentationCore.dll", version:"3.0.6920.4021", min_version:"3.0.6920.0", dir:net3path);
  missing += hotfix_is_vulnerable(os:"5.1", file:"PresentationCore.dll", version:"3.0.6920.5810", min_version:"3.0.6920.5700", dir:net3path);
  missing += hotfix_is_vulnerable(os:"5.2", file:"PresentationCore.dll", version:"3.0.6920.4021", min_version:"3.0.6920.0", dir:net3path);
  missing += hotfix_is_vulnerable(os:"5.2", file:"PresentationCore.dll", version:"3.0.6920.5810", min_version:"3.0.6920.5700", dir:net3path);
  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2656407");
  vuln += missing;

  # .NET Framework 3.0 on Windows Vista / Windows Server 2008
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.0", file:"PresentationCore.dll", version:"3.0.6920.4213", min_version:"3.0.6920.0", dir:net3path);
  missing += hotfix_is_vulnerable(os:"6.0", file:"PresentationCore.dll", version:"3.0.6920.5794", min_version:"3.0.6920.5700", dir:net3path);
  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2656409");
  vuln += missing;

  # .NET Framework 3.5.1 on Windows 7 / Server 2008 R2
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.1", sp:0, file:"PresentationCore.dll", version:"3.0.6920.5809", min_version:"3.0.6920.5700", dir:net3path);
  missing += hotfix_is_vulnerable(os:"6.1", sp:0, file:"PresentationCore.dll", version:"3.0.6920.5005", min_version:"3.0.6920.5000", dir:net3path);

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2656410");
  vuln += missing;

  # .NET Framework 3.5.1 on Windows 7 SP1 / Server 2008 R2 SP1
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"PresentationCore.dll", version:"3.0.6920.5794", min_version:"3.0.6920.5700", dir:net3path);
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"PresentationCore.dll", version:"3.0.6920.5448", min_version:"3.0.6920.5000", dir:net3path);

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2633873");
  vuln += missing;
}
# .NET Framework 4.0 on all supported versions of Windows
missing = 0;
missing += hotfix_is_vulnerable(os:"5.1", file:"PresentationCore.dll", version:"4.0.30319.275", min_version:"4.0.30319.0",   dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
missing += hotfix_is_vulnerable(os:"5.1", file:"PresentationCore.dll", version:"4.0.30319.550", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
missing += hotfix_is_vulnerable(os:"5.2", file:"PresentationCore.dll", version:"4.0.30319.275", min_version:"4.0.30319.0",   dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
missing += hotfix_is_vulnerable(os:"5.2", file:"PresentationCore.dll", version:"4.0.30319.550", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
missing += hotfix_is_vulnerable(os:"6.0", file:"PresentationCore.dll", version:"4.0.30319.275", min_version:"4.0.30319.0",   dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
missing += hotfix_is_vulnerable(os:"6.0", file:"PresentationCore.dll", version:"4.0.30319.550", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
missing += hotfix_is_vulnerable(os:"6.1", file:"PresentationCore.dll", version:"4.0.30319.275", min_version:"4.0.30319.0",   dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
missing += hotfix_is_vulnerable(os:"6.1", file:"PresentationCore.dll", version:"4.0.30319.550", min_version:"4.0.30319.400", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2656405");
vuln += missing;

################################################################
# Windows Checks                                               #
################################################################

#######################
# KB2676562           #
#######################
missing = 0;
# Windows 7 / 2008 R2
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"Win32k.sys", version:"6.1.7601.21955", min_version:"6.1.7601.21000", dir:"\system32");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"Win32k.sys", version:"6.1.7601.17803", min_version:"6.1.7601.17000", dir:"\system32");
missing += hotfix_is_vulnerable(os:"6.1", sp:0, file:"Win32k.sys", version:"6.1.7600.21179", min_version:"6.1.7600.20000", dir:"\system32");
missing += hotfix_is_vulnerable(os:"6.1", sp:0, file:"Win32k.sys", version:"6.1.7600.16988", min_version:"6.1.7600.16000", dir:"\system32");

# Windows Vista / 2008
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"Win32k.sys", version:"6.0.6002.22831", min_version:"6.0.6002.22000", dir:"\system32");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"Win32k.sys", version:"6.0.6002.18607", min_version:"6.0.6002.18000", dir:"\system32");

# Windows 2003 / XP 64-bit
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"Win32k.sys", version:"5.2.3790.4980", dir:"\system32");

# Windows XP 32-bit
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"Win32k.sys", version:"5.1.2600.6206", dir:"\system32");
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:'2676562');
vuln+= missing;

################################
# WinSxS Checks                #
################################
winsxs = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\WinSxS", string:rootfile);

#######################
# KB2659262           #
#######################
kb = '2659262';
files = list_dir(basedir:winsxs, level:0, dir_pat:'microsoft.windows.gdiplus', file_pat:'^gdiplus\\.dll$');

# Windows XP / 2003
vuln += hotfix_check_winsxs(os:'5.1', sp:3, files:files, versions:make_list('5.2.6002.22791'), bulletin:bulletin, kb:kb);
vuln += hotfix_check_winsxs(os:'5.2', sp:2, files:files, versions:make_list('5.2.6002.22791'), bulletin:bulletin, kb:kb);

# Windows Vista / 2008
versions = make_list('5.2.6002.18581', '5.2.6002.22795', '6.0.6002.18581', '6.0.6002.22795');
max_versions = make_list('5.2.6002.20000', '5.2.6002.99999', '6.0.6002.20000', '6.0.6002.99999');
vuln += hotfix_check_winsxs(os:'6.0', sp:2, files:files, versions:versions, max_versions:max_versions, bulletin:bulletin, kb:kb);

# Windows 7 / 2008 R2
versions = make_list('5.2.7600.17007', '5.2.7600.21198', '5.2.7601.17825', '5.2.7601.21977', '6.1.7600.17007', '6.1.7600.21198', '6.1.7601.17825', '6.1.7601.21977');
max_versions = make_list('5.2.7600.20000', '5.2.7600.99999', '5.2.7601.20000', '5.2.7601.99999', '6.1.7600.20000', '6.1.7600.99999', '6.1.7601.20000', '6.1.7601.99999');
vuln += hotfix_check_winsxs(os:'6.1', files:files, versions:versions, max_versions:max_versions, bulletin:bulletin, kb:kb);

#######################
# KB2658846           #
#######################
kb = '2658846';
files = list_dir(basedir:winsxs, level:0, dir_pat:'microsoft-windows-directwrite', file_pat:'^Dwrite\\.dll$');

# Windows Vista / Windows Server 2008
vuln += hotfix_check_winsxs(os:'6.0', files:files, versions:make_list('7.0.6002.18592', '7.0.6002.22807'), max_versions:make_list('7.0.6002.20000', '7.0.6002.99999'), bulletin:bulletin, kb:kb);

# Windows 7 2008 R2
versions = make_list('6.1.7600.16972', '6.1.7600.21162', '6.1.7601.17789', '6.1.7601.21935');
max_versions = make_list('6.1.7600.20000', '6.1.7600.99999', '6.1.7601.20000', '');
vuln += hotfix_check_winsxs(os:'6.1', files:files, versions:versions, max_versions:max_versions, bulletin:bulletin, kb:kb);

#######################
# KB2660649           #
#######################
kb = '2660649';

# Windows XP / Windows Server 2003
#(hotfix_check_sp(xp:4, win2003:3) > 0 && (version_cmp(a:ver, b:'1.7.2600.6189') >= 0)) ||

base_path = hotfix_get_programfilesdir();
if (!base_path) base_path = hotfix_get_programfilesdirx86();

if (!base_path) audit(AUDIT_PATH_NOT_DETERMINED, "Common Files");

full_path = hotfix_append_path(path:base_path, value:"\windows journal");

if (
  # Vista
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"jnwdrv.dll", version:"0.3.6002.22789", min_version:"0.3.6002.20000", path:full_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"jnwdrv.dll", version:"0.3.6002.18579", min_version:"0.3.6002.18000", path:full_path, bulletin:bulletin, kb:kb) ||

  # Windows 7
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"jnwdrv.dll", version:"0.3.7601.21955", min_version:"0.3.7601.18000", path:full_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"jnwdrv.dll", version:"0.3.7601.17803", min_version:"0.3.7601.16000", path:full_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"jnwdrv.dll", version:"0.3.7600.21179", min_version:"0.3.7600.18000", path:full_path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"jnwdrv.dll", version:"0.3.7600.16988", min_version:"0.3.7600.16000", path:full_path, bulletin:bulletin, kb:kb)
)
  vuln += 1;
hotfix_check_fversion_end();
#######################
# Report              #
#######################
if (vuln > 0)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
