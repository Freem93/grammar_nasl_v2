#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67209);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/01/15 21:14:37 $");

  script_cve_id(
    "CVE-2013-3129",
    "CVE-2013-3131",
    "CVE-2013-3132",
    "CVE-2013-3133",
    "CVE-2013-3134",
    "CVE-2013-3171",
    "CVE-2013-3178"
  );
  script_bugtraq_id(
    60932,
    60933,
    60934,
    60935,
    60937,
    60938,
    60978
  );
  script_osvdb_id(
    94954,
    94955,
    94956,
    94957,
    94958,
    94959,
    94960
  );
  script_xref(name:"MSFT", value:"MS13-052");
  script_xref(name:"IAVB", value:"2013-B-0071");

  script_name(english:"MS13-052: Vulnerabilities in .NET Framework and Silverlight Could Allow Remote Code Execution (2861561)");
  script_summary(english:"Checks version of Silverlight.exe / .NET .dll files");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The .NET Framework install on the remote Windows host could allow
arbitrary code execution."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of the .NET Framework installed on the remote host is
reportedly affected by the following vulnerabilities :

  - A vulnerability exists in the way that affected
    components handle specially crafted TrueType font
    files that could lead to remote code execution.  An
    attacker could leverage this issue by enticing a user
    to open a specially crafted TrueType font file.
    (CVE-2013-3129)

  - The .NET Framework does not properly handle
    multidimensional arrays of small structures, which
    could lead to remote code execution. (CVE-2013-3131)

  - The .NET Framework does not properly validate the
    permissions of certain objects performing reflection.
    This could allow an attacker to elevate their privileges
    and take complete control of the system.
    (CVE-2013-3132)

  - The .NET Framework does not properly validate the
    permissions of objects involved with reflection, which
    could lead to an elevation of privileges.
    (CVE-2013-3133)

  - The .NET Framework is affected by a remote code
    execution vulnerability due to the way in which it
    allocates arrays of small structures. (CVE-2013-3134)

  - The .NET Framework does not properly validate the
    permissions for delegate objects during serialization,
    which could lead to an elevation of privileges.
    (CVE-2013-3171)

  - Microsoft Silverlight does not properly handle null
    pointers, which could lead to remote code execution.
    (CVE-2013-3178)

An attacker may be able to leverage these vulnerabilities to execute
arbitrary code on the affected system if a user can be tricked into
viewing a specially crafted web page using a web browser that can run
XAML Browser Applications (XBAPs) or Silverlight applications."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-052");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for .NET Framework 1.0, 1.1,
2.0, 3.0, 3.5, 3.5.1, 4.0, and 4.5 as well as Silverlight 5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:silverlight");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "silverlight_detect.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");
include("smb_reg_query.inc");

# Windows Embedded is not supported by Nessus
# There are cases where this plugin is flagging embedded
# hosts improperly since this update does not apply
# to those machines
productname = get_kb_item("SMB/ProductName");
if ("Windows Embedded" >< productname)
  exit(0, "Nessus does not support bulletin / patch checks for Windows Embedded.");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS13-052';
kbs = make_list(
#  "2833951", # Not checked in smb_nt_ms12-074
              # Media Center Edition Service Pack 3 and Tablet PC Edition Service Pack 3 only
  "2833941", # .NET 1.1 XP SP3, Server 2003 SP2 x64, Vista SP2, 2008 SP2
  "2833940", # .NET 2.0 XP SP3, Server 2003 SP2
  "2844285", # .NET 2.0 XP SP3, Server 2003 SP2
  "2832411", # .NET 3.0 XP SP3, Server 2003 SP2
  "2840629", # .NET 3.5 XP SP3, Server 2003 SP2, Vista SP2, 2008 SP2
  "2832407", # .NET 4 XP SP3, Server 2003 SP2, Vista SP2, 2008 SP2
  "2835393", # .NET 4 XP SP3, Server 2003 SP2, Vista SP2, 2008 SP2, 7, 2008 R2
  "2840628", # .NET 4 XP SP3, Server 2003 SP2, Vista SP2, 2008 SP2, 7, 2008 R2
  "2833949", # .NET 1.1 Server 2003 x86
  "2833947", # .NET 2.0 Vista SP2, Server 2008 SP2
  "2844287", # .NET 2.0 Vista SP2, Server 2008 SP2
  "2832412", # .NET 3.0 Vista SP2, Server 2008 SP2
  "2835622", # .NET 4.5 Vista SP2, Server 2008 SP2
  "2833957", # .NET 4.5 Vista SP2, 2008 SP2, 7 SP1, 2008 R2 SP1
  "2840642", # .NET 4.5 Vista SP2, 2008 SP2, 7 SP1, 2008 R2 SP1
  "2832414", # .NET 3.5.1 Windows 7 SP1, Server 2008 R2 SP1
  "2833946", # .NET 3.5.1 Windows 7 SP1, Server 2008 R2 SP1
  "2840631", # .NET 3.5.1 Windows 7 SP1, Server 2008 R2 SP1
  "2844286", # .NET 3.5.1 Windows 7 SP1, Server 2008 R2 SP1
  "2832418", # .NET 3.5 Windows 8, Server 2012
  "2833959", # .NET 3.5 Windows 8, Server 2012
  "2840633", # .NET 3.5 Windows 8, Server 2012
  "2844289", # .NET 3.5 Windows 8, Server 2012
  "2833958", # .NET 4.5 Windows 8, Server 2012
  "2840632", # .NET 4.5 Windows 8, Server 2012
  "2847559"  # Silverlight
);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
win_ver = get_kb_item_or_exit('SMB/WindowsVersion');

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'1', win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

#  The .NET Framework is not applicable on Server Core installations of Windows
#  Server 2008 for 32-bit systems Service Pack 2 and Windows Server 2008 for
#  x64-based systems Service Pack 2.
if (win_ver == '6.0' && hotfix_check_server_core() == 1)
  audit(AUDIT_WIN_SERVER_CORE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

assembly_dir_30 = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\.NETFramework\AssemblyFolders\v3.0\All Assemblies In");

assembly_dir_35 = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\.NETFramework\AssemblyFolders\v3.5\All Assemblies In");
RegCloseKey(handle:hklm);

close_registry();

vuln = 0;

# Silverlight 5.x
ver = get_kb_item("SMB/Silverlight/Version");
fix = '5.1.20513.0';

if (!isnull(ver) && ver =~ '^5\\.' && ver_compare(ver:ver, fix:fix) == -1)
{
  path = get_kb_item("SMB/Silverlight/Path");
  report +=
    '\n  Product           : Microsoft Silverlight' +
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix + '\n';
  hotfix_add_report(report, bulletin:bulletin, kb:"2847559");
  vuln++;
}

########## KB2833949 ###########
#  .NET Framework 1.1 SP 1     #
#  Windows Server 2003 x86 SP2 #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x86", file:"Mscorlib.dll", version:"1.1.4322.2503", dir:"\Microsoft.NET\Framework\v1.1.4322");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2833949");
vuln += missing;

########## KB2833941 ###########
#  .NET Framework 1.1 SP 1     #
#  Windows XP SP3,             #
#  Windows Server 2003 64-bit, #
#  Vista SP2,                  #
#  Server 2008 SP2             #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.Web.dll", version:"1.1.4322.2503", dir:"\Microsoft.NET\Framework\v1.1.4322");
missing += hotfix_is_vulnerable(os:"5.2", arch:"x64", sp:2, file:"System.Web.dll", version:"1.1.4322.2503", dir:"\Microsoft.NET\Framework\v1.1.4322");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Web.dll", version:"1.1.4322.2503", dir:"\Microsoft.NET\Framework\v1.1.4322");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:'2833941');
vuln += missing;

########## KB2844287 ###########
#  .NET Framework 2.0 SP2      #
#  Vista SP2                   #
#  Server 2008 SP2             #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.configuration.dll", version:"2.0.50727.7035", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.configuration.dll", version:"2.0.50727.4246", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2844287");
vuln += missing;

########## KB2844285 ###########
#  .NET Framework 2.0 SP2      #
#  Windows XP SP3,             #
#  Windows 2003 SP2            #
################################
missing = 0;
# Windows XP SP3
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.XML.dll", version:"2.0.50727.3654", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.XML.dll", version:"2.0.50727.7037", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
# Server 2003 SP2
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.XML.dll", version:"2.0.50727.3654", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.XML.dll", version:"2.0.50727.7037", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2844285");
vuln += missing;

########## KB2833940 ###########
#  .NET Framework 2.0 SP2      #
#  Windows XP SP3,             #
#  Windows 2003 SP2            #
################################
missing = 0;
# Windows XP SP3
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"Mscorlib.dll", version:"2.0.50727.3649", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"Mscorlib.dll", version:"2.0.50727.7026", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
# Server 2003 SP2
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mscorlib.dll", version:"2.0.50727.3649", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mscorlib.dll", version:"2.0.50727.7026", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2833940");
vuln += missing;

########## KB2833947 ###########
#  .NET Framework 2.0 SP2      #
#  Windows Vista SP2,          #
#  Server 2008 SP2             #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"mscorlib.dll", version:"2.0.50727.7025", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"mscorlib.dll", version:"2.0.50727.4241", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2833947");
vuln += missing;

######### KB2832411 ###########
#  .NET Framework 3.0 SP2     #
#  Windows XP SP 3,           #
#  Server 2003 SP2            #
###############################
if (!isnull(assembly_dir_30))
{
  missing = 0;
  missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"PresentationCore.dll",    version:"3.0.6920.4050", min_version:"3.0.6920.0", path:assembly_dir_30);
  missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"PresentationCore.dll",    version:"3.0.6920.7045", min_version:"3.0.6920.5700", path:assembly_dir_30);
  missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"PresentationCore.dll",    version:"3.0.6920.4050", min_version:"3.0.6920.0", path:assembly_dir_30);
  missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"PresentationCore.dll",    version:"3.0.6920.7045", min_version:"3.0.6920.5700", path:assembly_dir_30);

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2832411");
  vuln += missing;
}

######### KB2832412 ###########
#  .NET Framework 3.0 SP2     #
#  Windows Vista SP2,         #
#  Server 2008 SP2            #
###############################
if (!isnull(assembly_dir_30))
{
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"Presentationcore.dll",    version:"3.0.6920.4216", min_version:"3.0.6920.0", path:assembly_dir_30);
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"Presentationcore.dll",    version:"3.0.6920.7036", min_version:"3.0.6920.5700", path:assembly_dir_30);

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2832412");
  vuln += missing;
}

########## KB2844289 ###########
#  .NET Framework 3.5          #
#  Windows 8,                  #
#  Server 2012                 #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.xml.dll", version: "2.0.50727.6411", min_version:"2.0.50727.6000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.xml.dll", version: "2.0.50727.7035", min_version:"2.0.50727.7000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2844289");
vuln += missing;

########## KB2840633 ###########
#  .NET Framework 3.5          #
#  Windows 8,                  #
#  Server 2012                 #
################################
if (!isnull(assembly_dir_35))
{
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.data.linq.dll", version: "3.5.30729.6404", min_version:"3.5.30729.6000", path:assembly_dir_35);
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.data.linq.dll", version: "3.5.30729.7048", min_version:"3.5.30729.7000", path:assembly_dir_35);

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2840633");
  vuln += missing;
}

######### KB2840629 ###########
#  .NET Framework 3.5 SP1     #
#  Windows XP SP3,            #
#  Server 2003 SP2            #
#  Vista SP2                  #
#  Server 2008 SP2            #
###############################
if (!isnull(assembly_dir_35))
{
  missing = 0;
  missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.Data.Linq.dll",    version:"3.5.30729.4052", min_version:"3.5.30729.1", path:assembly_dir_35);
  missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.Data.Linq.dll",    version:"3.5.30729.7049", min_version:"3.5.30729.5400", path:assembly_dir_35);

  missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Data.Linq.dll",    version:"3.5.30729.4052", min_version:"3.5.30729.1", path:assembly_dir_35);
  missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Data.Linq.dll",    version:"3.5.30729.7049", min_version:"3.5.30729.5400", path:assembly_dir_35);

  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Data.Linq.dll",    version:"3.5.30729.4052", min_version:"3.5.30729.1", path:assembly_dir_35);
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Data.Linq.dll",    version:"3.5.30729.7049", min_version:"3.5.30729.5400", path:assembly_dir_35);

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2840629");
  vuln += missing;
}

########## KB2833959 ###########
#  .NET Framework 3.5          #
#  Windows 8,                  #
#  Server 2012                 #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"Mscorlib.dll", version :  "2.0.50727.6407", min_version:"2.0.50727.6000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"Mscorlib.dll", version :  "2.0.50727.7025", min_version:"2.0.50727.7000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2833959");
vuln += missing;


########## KB2832418 ###########
#  .NET Framework 3.5          #
#  Windows 8,                  #
#  Server 2012                 #
################################
if (!isnull(assembly_dir_35))
{
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.printing.dll",    version: "3.0.6920.6402", min_version:"3.0.6920.6000", path:assembly_dir_35);
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.printing.dll",    version: "3.0.6920.7036", min_version:"3.0.6920.7000", path:assembly_dir_35);

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2832418");
  vuln += missing;
}

########## KB2844286 ###########
#  .NET Framework 3.5.1        #
#  Windows 7 SP1               #
#  Server 2008 R2 SP1          #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.xml.dll", version: "2.0.50727.5476", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.xml.dll", version: "2.0.50727.7035", min_version:"2.0.50727.5600", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2844286");
vuln += missing;

######### KB2840631 ###########
#  .NET Framework 3.5.1       #
#  Windows 7 SP1,             #
#  Server 2008 R2 SP1         #
###############################
if (!isnull(assembly_dir_35))
{
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.data.linq.dll", version:"3.5.30729.5455", min_version:"3.5.30729.4000", path:assembly_dir_35);
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.data.linq.dll", version:"3.5.30729.7048", min_version:"3.5.30729.5600", path:assembly_dir_35);

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2840631");
  vuln += missing;
}

######### KB2833946 ###########
#  .NET Framework 3.5.1       #
#  Windows 7 SP1,             #
#  Server 2008 R2 SP1         #
###############################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"mscorlib.dll", version:"2.0.50727.5472", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"mscorlib.dll", version:"2.0.50727.7025", min_version:"2.0.50727.5600", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2833946");
vuln += missing;

######### KB2832414 ###########
#  .NET Framework 3.5.1       #
#  Windows 7 SP1,             #
#  Server 2008 R2 SP1         #
###############################
if (!isnull(assembly_dir_30))
{
  # .NET Framework 3.5.1 on Windows 7 SP1 / Server 2008 R2 SP1
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"PresentationCore.dll",    version:"3.0.6920.5453", min_version:"3.0.6920.5000", path:assembly_dir_30);
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"PresentationCore.dll",    version:"3.0.6920.7036", min_version:"3.0.6920.5700", path:assembly_dir_30);

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2832414");
  vuln += missing;
}

########## KB2840628 ###########
#  .NET Framework 4.0          #
#  Windows XP SP3,             #
#  Windows XP SP2 x64,         #
#  Windows 2003 SP2,           #
#  Windows Vista SP2,          #
#  Windows 7,                  #
#  Windows Server 2008 SP2,    #
#  Windows Server 2008 R2      #
################################
missing = 0;
# Windows XP SP3
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"PresentationCore.dll", version:"4.0.30319.1015", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"PresentationCore.dll", version:"4.0.30319.2022", min_version:"4.0.30319.2000", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");

# Windows XP SP2 x64 / Server 2003 SP2
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"PresentationCore.dll", version:"4.0.30319.1015", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"PresentationCore.dll", version:"4.0.30319.2022", min_version:"4.0.30319.2000", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");

# Windows Vista SP2 / Server 2008 SP2
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"PresentationCore.dll", version:"4.0.30319.1015", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"PresentationCore.dll", version:"4.0.30319.2022", min_version:"4.0.30319.2000", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");

# Windows 7 / 2008 R2
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"PresentationCore.dll", version:"4.0.30319.1015", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"PresentationCore.dll", version:"4.0.30319.2022", min_version:"4.0.30319.2000", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2840628");
vuln += missing;


########## KB2832407 ###########
#  .NET Framework 4.0          #
#  Windows XP SP3,             #
#  Windows XP SP2 x64,         #
#  Windows 2003 SP2,           #
#  Windows Vista SP2,          #
#  Windows 2008 SP2            #
################################
missing = 0;
# Windows XP SP3
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"PresentationCore.dll", version:"4.0.30319.1005", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"PresentationCore.dll", version:"4.0.30319.2009", min_version:"4.0.30319.2000", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");

# Windows XP SP2 x64 / Server 2003 SP2
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"PresentationCore.dll", version:"4.0.30319.1005", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"PresentationCore.dll", version:"4.0.30319.2009", min_version:"4.0.30319.2000", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");

# Windows Vista SP2 / Server 2008 SP2
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"PresentationCore.dll", version:"4.0.30319.1005", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"PresentationCore.dll", version:"4.0.30319.2009", min_version:"4.0.30319.2000", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2832407");
vuln += missing;


########## KB2835393 ###########
#  .NET Framework 4.0          #
#  Windows XP SP3,             #
#  Windows XP SP2 x64,         #
#  Windows 2003 SP2,           #
#  Windows Vista SP2,          #
#  Windows 7,                  #
#  Windows Server 2008 SP2,    #
#  Windows Server 2008 R2      #
################################
missing = 0;
# Windows XP SP3
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"Mscorlib.dll", version:"4.0.30319.1008", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"Mscorlib.dll", version:"4.0.30319.2012", min_version:"4.0.30319.2000", dir:"\Microsoft.NET\Framework\v4.0.30319");

# Windows XP SP2 x64 / Server 2003 SP2
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mscorlib.dll", version:"4.0.30319.1008", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mscorlib.dll", version:"4.0.30319.2012", min_version:"4.0.30319.2000", dir:"\Microsoft.NET\Framework\v4.0.30319");

# Windows Vista SP2 / Server 2008 SP2
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mscorlib.dll", version:"4.0.30319.1008", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mscorlib.dll", version:"4.0.30319.2012", min_version:"4.0.30319.2000", dir:"\Microsoft.NET\Framework\v4.0.30319");

# Windows 7 / 2008 R2
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mscorlib.dll", version:"4.0.30319.1008", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mscorlib.dll", version:"4.0.30319.2012", min_version:"4.0.30319.2000", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2835393");
vuln += missing;

########## KB2840632 ###########
#  .NET Framework 4.5          #
#  Windows 8                   #
#  Server 2012                 #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.xml.dll", version: "4.0.30319.18058", min_version:"4.0.30319.17900", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.xml.dll", version: "4.0.30319.19112", min_version:"4.0.30319.19000", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2840632");
vuln += missing;

########## KB2840642 ###########
#  .NET Framework 4.5          #
#  Windows Vista SP2,          #
#  Server 2008 SP2,            #
#  Windows 7 SP1,              #
#  Windows 2008 R2 SP1         #
################################
missing = 0;
# Windows Vista SP2 / Server 2008 SP2
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.xml.dll", version: "4.0.30319.18060", min_version:"4.0.30319.17900", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.xml.dll", version: "4.0.30319.19115", min_version:"4.0.30319.19000", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Windows 7 SP1 / 2008 R2 SP1
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.xml.dll", version: "4.0.30319.18060", min_version:"4.0.30319.17900", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.xml.dll", version: "4.0.30319.19115", min_version:"4.0.30319.19000", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2840642");
vuln += missing;

########## KB2835622 ###########
#  .NET Framework 4.5          #
#  Windows Vista SP2,          #
#  Server 2008 SP2,            #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"Wpftxt_v0400.dll", version: "4.0.30319.18049", min_version:"4.0.30319.17900", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"Wpftxt_v0400.dll", version: "4.0.30319.19077", min_version:"4.0.30319.19000", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2835622");
vuln += missing;

########## KB2833957 ###########
#  .NET Framework 4.5          #
#  Windows Vista SP2,          #
#  Server 2008 SP2,            #
#  Windows 7 SP1,              #
#  Windows 2008 R2 SP1         #
################################
missing = 0;
# Windows Vista SP2 / Server 2008 SP2
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mscorlib.dll", version: "4.0.30319.18052", min_version:"4.0.30319.17900", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mscorlib.dll", version: "4.0.30319.19080", min_version:"4.0.30319.19000", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Windows 7 SP1 / 2008 R2 SP1
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mscorlib.dll", version: "4.0.30319.18052", min_version:"4.0.30319.17900", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mscorlib.dll", version: "4.0.30319.19080", min_version:"4.0.30319.19000", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2833957");
vuln += missing;

########## KB2833958 ###########
#  .NET Framework 4.5          #
#  Windows 8                   #
#  Server 2012                 #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"Mscorlib.dll", version :  "4.0.30319.18051", min_version:"4.0.30319.17900", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"Mscorlib.dll", version :  "4.0.30319.19079", min_version:"4.0.30319.19000", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2833958");
vuln += missing;

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
