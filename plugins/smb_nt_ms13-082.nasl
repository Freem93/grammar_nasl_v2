#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70334);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/19 18:02:19 $");

  script_cve_id("CVE-2013-3128", "CVE-2013-3860", "CVE-2013-3861");
  script_bugtraq_id(62807, 62819, 62820);
  script_osvdb_id(98208, 98215, 98216);
  script_xref(name:"MSFT", value:"MS13-082");
  script_xref(name:"IAVA", value:"2013-A-0187");

  script_name(english:"MS13-082: Vulnerabilities in .NET Framework Could Allow Remote Code Execution (2878890)");
  script_summary(english:"Checks version of .NET .dll files");

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
    components handle specially crafted OpenType fonts
    (OTF) that could lead to remote code execution.  An
    attacker could leverage this issue by enticing a user
    to visit a web page containing a specially crafted OTF
    font file. (CVE-2013-3128)

  - The .NET Framework is affected by a denial of service
    vulnerability when parsing a specially crafted document
    type definition (DTD) for XML data. (CVE-2013-3860)

  - The .NET Framework is affected by a denial of service
    vulnerability when parsing specially crafted
    JavaScript Object Notation (JSON) data. (CVE-2013-3861)"
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-082");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for .NET Framework 2.0, 3.0,
3.5, 3.5.1, 4.0, and 4.5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS13-082';
kbs = make_list(
  "2877175",  # .NET 4.5.1 Vista, 2008 SP2
  "2861702",  # .NET 4.5 Windows 8, Server 2012
  "2861208",  # .NET 4.5 Vista SP2, Server 2008 SP2, 7, 2008 R2
  "2861193",  # .NET 4.5 Vista SP2, Server 2008 SP2
  "2858302",  # .NET 4 XP SP3, Server 2003 SP2, Vista SP2, 2008 SP2, 7, 2008 R2
  "2861188",  # .NET 4 XP SP3, Server 2003 SP2, Vista SP2, 2008 SP2
  "2861698",  # .NET 3.5.1 Windows 7 SP1, Server 2008 R2 SP1
  "2863240",  # .NET 3.5.1 Windows 7 SP1, Server 2008 R2 SP1
  "2861191",  # .NET 3.5.1 Windows 7 SP1, Server 2008 R2 SP1
  "2861697",  # .NET 3.5 SP1 XP SP3, Server 2003 SP2, Vista SP2, 2008 SP2
  "2863243",  # .NET 3.5 Windows 8, Server 2012
  "2861704",  # .NET 3.5 Windows 8, Server 2012
  "2861194",  # .NET 3.5 Windows 8, Server 2012
  "2876919",  # .NET 3.5 Windows 8.1, Server 2012 R2
  "2861190",  # .NET 3.0 Vista SP2, Server 2008 SP2
  "2861189",  # .NET 3.0 XP SP3, Server 2003 SP2
  "2863253",  # .NET 2.0 Vista SP2, Server 2008 SP2
  "2863239"   # .NET 2.0 XP SP3, Server 2003 SP2
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
win_ver = get_kb_item_or_exit('SMB/WindowsVersion');

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

#  The .NET Framework is not applicable on Server Core installations of Windows
#  Server 2008 for 32-bit systems Service Pack 2 and Windows Server 2008 for
#  x64-based systems Service Pack 2.
if (win_ver == '6.0' && hotfix_check_server_core() == 1)
  audit(AUDIT_WIN_SERVER_CORE);

# RT 8.1 is not affected
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if (win_ver == '6.3' && "Windows Embedded" >< productname) exit(0, "The host is running "+productname+" and is, therefore, not affected.");

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

########## KB2877175 ############
#  .NET Framework 4.5.1 Preview #
#  Windows Vista SP2,           #
#  Server 2008 SP2,             #
#################################
missing = 0;
# Windows Vista SP2 / Server 2008 SP2
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"wpftxt_v0400.dll", version: "4.0.30319.18222", min_version:"4.0.30319.17900", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"wpftxt_v0400.dll", version: "4.0.30319.19221", min_version:"4.0.30319.19000", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2877175");
vuln += missing;

########## KB2861702 ###########
#  .NET Framework 4.5          #
#  Windows 8                   #
#  Server 2012                 #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.web.dll", version :  "4.0.30319.18056", min_version:"4.0.30319.17900", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.web.dll", version :  "4.0.30319.19109", min_version:"4.0.30319.19000", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2861702");
vuln += missing;

########## KB2861208 ###########
#  .NET Framework 4.5          #
#  Windows Vista SP2,          #
#  Server 2008 SP2,            #
#  Windows 7 SP1,              #
#  Windows 2008 R2 SP1         #
################################
missing = 0;
# Windows Vista SP2 / Server 2008 SP2
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Web.dll", version: "4.0.30319.18055", min_version:"4.0.30319.17900", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Web.dll", version: "4.0.30319.19108", min_version:"4.0.30319.19000", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Windows 7 SP1 / 2008 R2 SP1
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Web.dll", version: "4.0.30319.18055", min_version:"4.0.30319.17900", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Web.dll", version: "4.0.30319.19108", min_version:"4.0.30319.19000", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2861208");
vuln += missing;

########## KB2861193 ###########
#  .NET Framework 4.5          #
#  Windows Vista SP2,          #
#  Server 2008 SP2,            #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"Wpftxt_v0400.dll", version: "4.0.30319.18059", min_version:"4.0.30319.17900", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"Wpftxt_v0400.dll", version: "4.0.30319.19114", min_version:"4.0.30319.19000", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2861193");
vuln += missing;

########## KB2858302 ###########
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
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.Web.dll", version:"4.0.30319.1016", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.Web.dll", version:"4.0.30319.2026", min_version:"4.0.30319.2000", dir:"\Microsoft.NET\Framework\v4.0.30319");

# Windows XP SP2 x64 / Server 2003 SP2
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Web.dll", version:"4.0.30319.1016", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Web.dll", version:"4.0.30319.2026", min_version:"4.0.30319.2000", dir:"\Microsoft.NET\Framework\v4.0.30319");

# Windows Vista SP2 / Server 2008 SP2
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Web.dll", version:"4.0.30319.1016", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Web.dll", version:"4.0.30319.2026", min_version:"4.0.30319.2000", dir:"\Microsoft.NET\Framework\v4.0.30319");

# Windows 7 / 2008 R2
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Web.dll", version:"4.0.30319.1016", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Web.dll", version:"4.0.30319.2026", min_version:"4.0.30319.2000", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2858302");
vuln += missing;

########## KB2861188 ###########
#  .NET Framework 4.0          #
#  Windows XP SP3,             #
#  Windows XP SP2 x64,         #
#  Windows 2003 SP2,           #
#  Windows Vista SP2,          #
#  Windows 2008 SP2            #
################################
missing = 0;
# Windows XP SP3
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"PresentationCore.dll", version:"4.0.30319.1014", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"PresentationCore.dll", version:"4.0.30319.2021", min_version:"4.0.30319.2000", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");

# Windows XP SP2 x64 / Server 2003 SP2
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"PresentationCore.dll", version:"4.0.30319.1014", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"PresentationCore.dll", version:"4.0.30319.2021", min_version:"4.0.30319.2000", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");

# Windows Vista SP2 / Server 2008 SP2
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"PresentationCore.dll", version:"4.0.30319.1014", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"PresentationCore.dll", version:"4.0.30319.2021", min_version:"4.0.30319.2000", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2861188");
vuln += missing;

######### KB2861698 ###########
#  .NET Framework 3.5.1       #
#  Windows 7 SP1,             #
#  Server 2008 R2 SP1         #
###############################
if (!isnull(assembly_dir_35))
{
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.web.extensions.dll", version:"3.5.30729.5458", min_version:"3.5.30729.4000", path:assembly_dir_35);
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.web.extensions.dll", version:"3.5.30729.7057", min_version:"3.5.30729.5600", path:assembly_dir_35);

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2861698");
  vuln += missing;
}

########## KB2863240 ###########
#  .NET Framework 3.5.1        #
#  Windows 7 SP1               #
#  Server 2008 R2 SP1          #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.security.dll", version: "2.0.50727.5475", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.security.dll", version: "2.0.50727.7032", min_version:"2.0.50727.5600", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2863240");
vuln += missing;

######### KB2861191 ###########
#  .NET Framework 3.5.1       #
#  Windows 7 SP1,             #
#  Server 2008 R2 SP1         #
###############################
if (!isnull(assembly_dir_30))
{
  # .NET Framework 3.5.1 on Windows 7 SP1 / Server 2008 R2 SP1
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"presentationcffrasterizernative_v0300.dll", version:"3.0.6920.5459", min_version:"3.0.6920.5000", path:assembly_dir_30);
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"presentationcffrasterizernative_v0300.dll", version:"3.0.6920.7062", min_version:"3.0.6920.5700", path:assembly_dir_30);

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2861191");
  vuln += missing;
}

######### KB2861697 ###########
#  .NET Framework 3.5 SP1     #
#  Windows XP SP3,            #
#  Server 2003 SP2            #
#  Vista SP2                  #
#  Server 2008 SP2            #
###############################
if (!isnull(assembly_dir_35))
{
  missing = 0;
  missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.Web.Extensions.dll", version:"3.5.30729.4056", min_version:"3.5.30729.1", path:assembly_dir_35);
  missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.Web.Extensions.dll", version:"3.5.30729.7056", min_version:"3.5.30729.5400", path:assembly_dir_35);

  missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Web.Extensions.dll", version:"3.5.30729.4056", min_version:"3.5.30729.1", path:assembly_dir_35);
  missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Web.Extensions.dll", version:"3.5.30729.7056", min_version:"3.5.30729.5400", path:assembly_dir_35);

  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Web.Extensions.dll", version:"3.5.30729.4056", min_version:"3.5.30729.1", path:assembly_dir_35);
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Web.Extensions.dll", version:"3.5.30729.7056", min_version:"3.5.30729.5400", path:assembly_dir_35);

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2861697");
  vuln += missing;
}

########## KB2863243 ###########
#  .NET Framework 3.5          #
#  Windows 8,                  #
#  Server 2012                 #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.security.dll", version : "2.0.50727.6410", min_version:"2.0.50727.6000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.security.dll", version : "2.0.50727.7032", min_version:"2.0.50727.7000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2863243");
vuln += missing;

########## KB2861704 ###########
#  .NET Framework 3.5          #
#  Windows 8,                  #
#  Server 2012                 #
################################
if (!isnull(assembly_dir_35))
{
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.web.extensions.dll", version: "3.5.30729.6407", min_version:"3.5.30729.6000", path:assembly_dir_35);
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.web.extensions.dll", version: "3.5.30729.7057", min_version:"3.5.30729.7000", path:assembly_dir_35);

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2861704");
  vuln += missing;
}

########## KB2861194 ###########
#  .NET Framework 3.5          #
#  Windows 8,                  #
#  Server 2012                 #
################################
if (!isnull(assembly_dir_35))
{
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"presentationcffrasterizernative_v0300.dll", version: "3.0.6920.6409", min_version:"3.0.6920.6000", path:assembly_dir_35);
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"presentationcffrasterizernative_v0300.dll", version: "3.0.6920.7062", min_version:"3.0.6920.7000", path:assembly_dir_35);

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2861194");
  vuln += missing;
}

########## KB2876919 ###########
#  .NET Framework 3.5          #
#  Windows 8.1,                #
#  Server 2012 R2              #
################################
if (!isnull(assembly_dir_35))
{
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"presentationcffrasterizernative_v0300.dll", version: "3.0.6920.7821", min_version:"3.0.6920.7000", path:assembly_dir_35);

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2876919");
  vuln += missing;
}

######### KB2861190 ###########
#  .NET Framework 3.0 SP2     #
#  Windows Vista SP2,         #
#  Server 2008 SP2            #
###############################
if (!isnull(assembly_dir_30))
{
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"presentationcffrasterizernative_v0300.dll", version:"3.0.6920.4218", min_version:"3.0.6920.0", path:assembly_dir_30);
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"presentationcffrasterizernative_v0300.dll", version:"3.0.6920.7062", min_version:"3.0.6920.5700", path:assembly_dir_30);

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2861190");
  vuln += missing;
}

######### KB2861189 ###########
#  .NET Framework 3.0 SP2     #
#  Windows XP SP 3,           #
#  Server 2003 SP2            #
###############################
if (!isnull(assembly_dir_30))
{
  missing = 0;
  # XP SP3
  missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"PresentationCFFRasterizerNative_v0300.dll", version:"3.0.6920.4058", min_version:"3.0.6920.0", path:assembly_dir_30);
  missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"PresentationCFFRasterizerNative_v0300.dll", version:"3.0.6920.7061", min_version:"3.0.6920.5700", path:assembly_dir_30);
  # XP x64 / Server 2003 SP2
  missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"PresentationCFFRasterizerNative_v0300.dll", version:"3.0.6920.4058", min_version:"3.0.6920.0", path:assembly_dir_30);
  missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"PresentationCFFRasterizerNative_v0300.dll", version:"3.0.6920.7061", min_version:"3.0.6920.5700", path:assembly_dir_30);

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2861189");
  vuln += missing;
}

########## KB2863253 ###########
#  .NET Framework 2.0 SP2      #
#  Windows Vista SP2,          #
#  Server 2008 SP2             #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.security.dll", version:"2.0.50727.4245", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.security.dll", version:"2.0.50727.7032", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2863253");
vuln += missing;

########## KB2863239 ###########
#  .NET Framework 2.0 SP2      #
#  Windows XP SP3,             #
#  Windows 2003 SP2            #
################################
missing = 0;
# Windows XP SP3
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.Security.dll", version:"2.0.50727.3652", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.Security.dll", version:"2.0.50727.7032", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
# Server 2003 SP2
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Security.dll", version:"2.0.50727.3652", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Security.dll", version:"2.0.50727.7032", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2863239");
vuln += missing;

# Reporting
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
