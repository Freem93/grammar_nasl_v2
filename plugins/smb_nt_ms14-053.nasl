#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77573);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2014-4072");
  script_bugtraq_id(69603);
  script_osvdb_id(111148);
  script_xref(name:"MSFT", value:"MS14-053");

  script_name(english:"MS14-053: Vulnerability in .NET Framework Could Allow Denial of Service (2990931)");
  script_summary(english:"Checks the version of the .NET files.");

  script_set_attribute(attribute:"synopsis", value:
"The version of the .NET Framework installed on the remote host is
affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of the Microsoft .NET Framework
that is affected by a vulnerability that allows a remote attacker to
cause a denial of service by sending specially crafted requests to an
ASP.NET web application running on the affected system.

Note that ASP.NET is not installed by default and ASP.NET must be
registered and enabled for the host to be affected.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS14-053");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for .NET Framework 1.1 SP1,
2.0 SP2, 3.0 SP2, 3.5, 3.5.1, 4.0, 4.5, 4.5.1, and 4.5.2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "microsoft_net_framework_installed.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");

# Windows Embedded is not supported by Nessus
# There are cases where this plugin is flagging embedded
# hosts improperly since this update does not apply
# to those machines
productname = get_kb_item("SMB/ProductName");
if ("Windows Embedded" >< productname)
  exit(0, "Nessus does not support bulletin / patch checks for Windows Embedded.");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS14-053';
kbs = make_list(
  "2972207",
  "2972211",
  "2972212",
  "2972213",
  "2972214",
  "2972215",
  "2972216",
  "2973112",
  "2973113",
  "2973114",
  "2973115",
  "2974268",
  "2974269",
  "2977765",
  "2977766"
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# Windows 2008 Server Server Core is not affected.
if ('6.0' >< get_kb_item("SMB/WindowsVersion") && hotfix_check_server_core()) audit(AUDIT_WIN_SERVER_CORE);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

dotnet_452_installed = FALSE;
dotnet_451_installed = FALSE;
dotnet_45_installed  = FALSE;

# Determine if .NET 4.5, 4.5.1, or 4.5.2 is installed
count = get_install_count(app_name:'Microsoft .NET Framework');
if (count > 0)
{
  installs = get_installs(app_name:'Microsoft .NET Framework');
  foreach install(installs[1])
  {
    ver = install["version"];
    if (ver == "4.5") dotnet_45_installed = TRUE;
    if (ver == "4.5.1") dotnet_451_installed = TRUE;
    if (ver == "4.5.2") dotnet_452_installed = TRUE;
  }
}

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
assembly_dir_30 = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\.NETFramework\AssemblyFolders\v3.0\All Assemblies In");
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

vuln = 0;

########## KB2977765 ###########
# .NET Framework 4.5.1 / 4.5.2 #
# Windows 8.1                  #
# Windows RT 8.1               #
# Windows Server 2012 R2       #
################################
missing = 0;
if (dotnet_451_installed || dotnet_452_installed)
{
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.runtime.serialization.dll", version:"4.0.30319.34209", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.runtime.serialization.dll", version:"4.0.30319.36213", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2977765");
vuln += missing;

########### KB2977766 ############
# .NET Framework 4.5/4.5.1/4.5.2 #
# Windows 8                      #
# Windows RT                     #
# Windows Server 2012            #
##################################
missing = 0;
if (dotnet_45_installed || dotnet_451_installed || dotnet_452_installed)
{
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.runtime.serialization.dll", version:"4.0.30319.34230", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.runtime.serialization.dll", version:"4.0.30319.36241", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2977766");
vuln += missing;

########### KB2972216 ############
# .NET Framework 4.5/4.5.1/4.5.2 #
# Windows Vista SP2              #
# Windows Server 2008 SP2        #
# Windows 7 SP1                  #
# Windows Server 2008 R2 SP1     #
##################################
missing = 0;
if (dotnet_45_installed || dotnet_451_installed || dotnet_452_installed)
{
  # Windows Vista/Server 2008 SP2
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.runtime.serialization.dll", version:"4.0.30319.34234", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # Windows 7/Server 2008 R2 SP1
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.runtime.serialization.dll", version:"4.0.30319.34234", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2972216");
vuln += missing;

########### KB2972215 ############
# .NET Framework 4               #
# Windows Vista SP2              #
# Windows Server 2008 SP2        #
# Windows 7 SP1                  #
# Windows Server 2008 R2 SP1     #
# Windows Server 2003 SP2        #
##################################
missing = 0;

# Windows Server 2003 SP2
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"system.runtime.serialization.dll", version:"4.0.30319.1026", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Windows Vista/Server 2008 SP2
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.runtime.serialization.dll", version:"4.0.30319.1026", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Windows 7/Server 2008 R2 SP1
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.runtime.serialization.dll", version:"4.0.30319.1026", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2972215");
vuln += missing;

########### KB2973112 ############
# .NET Framework 3.5.1           #
# Windows 7 SP1                  #
# Windows Server 2008 R2 SP1     #
##################################
if (!isnull(assembly_dir_30))
{
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.runtime.serialization.dll", version:"3.0.4506.5463", min_version:"3.0.4506.5000", path:assembly_dir_30);
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.runtime.serialization.dll", version:"3.0.4506.8635", min_version:"3.0.4506.7000", path:assembly_dir_30);

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2973112");
  vuln += missing;
}

########### KB2972211 ############
# .NET Framework 3.5.1           #
# Windows 7 SP1                  #
# Windows Server 2008 R2 SP1     #
##################################
missing = 0;

missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"mscorlib.dll", version:"2.0.50727.5485", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"mscorlib.dll", version:"2.0.50727.7071", min_version:"2.0.50727.7000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2972211");
vuln += missing;

########## KB2973114 ###########
# .NET Framework 3.5           #
# Windows 8.1                  #
# Windows Server 2012 R2       #
################################
if (!isnull(assembly_dir_30))
{
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.identitymodel.dll", version:"3.0.4506.8002", min_version:"3.0.4506.0", path:assembly_dir_30);

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2973114");
  vuln += missing;
}

########## KB2972213 ###########
# .NET Framework 3.5           #
# Windows 8.1                  #
# Windows Server 2012 R2       #
################################
missing = 0;

missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"mscorwks.dll", version:"2.0.50727.8009", min_version:"2.0.50727.7000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2972213");
vuln += missing;

########## KB2973113 ###########
# .NET Framework 3.5           #
# Windows 8                    #
# Windows Server 2012          #
################################
if (!isnull(assembly_dir_30))
{
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.identitymodel.dll", version:"3.0.4506.6415", min_version:"3.0.4506.6000", path:assembly_dir_30);
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.identitymodel.dll", version:"3.0.4506.8635", min_version:"3.0.4506.7000", path:assembly_dir_30);

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2973113");
  vuln += missing;
}
########## KB2972212 ###########
# .NET Framework 3.5           #
# Windows 8                    #
# Windows Server 2012          #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"mscorlib.dll", version:"2.0.50727.6421", min_version:"2.0.50727.6000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"mscorlib.dll", version:"2.0.50727.7071", min_version:"2.0.50727.7000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2972212");
vuln += missing;

########### KB2974269 ############
# .NET Framework 3.0 SP2         #
# Windows Vista SP2              #
# Windows Server 2008 SP2        #
##################################
if (!isnull(assembly_dir_30))
{
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.runtime.serialization.dll", version:"3.0.4506.4222", min_version:"3.0.4506.4000", path:assembly_dir_30);
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.runtime.serialization.dll", version:"3.0.4506.8635", min_version:"3.0.4506.5000", path:assembly_dir_30);

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2974269");
  vuln += missing;
}
########### KB2973115 ############
# .NET Framework 3.0 SP2         #
# Windows Server 2003 SP2        #
##################################
if (!isnull(assembly_dir_30))
{
  missing = 0;
  missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"system.runtime.serialization.dll", version:"3.0.4506.4068", min_version:"3.0.4506.4000", path:assembly_dir_30);

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2973115");
  vuln += missing;
}

########### KB2974268 ############
# .NET Framework 2.0 SP2         #
# Windows Vista SP2              #
# Windows Server 2008 SP2        #
##################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"mscorlib.dll", version:"2.0.50727.7071", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"mscorlib.dll", version:"2.0.50727.4253", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2974268");
vuln += missing;

########### KB2972214 ############
# .NET Framework 2.0 SP2         #
# Windows Server 2003 SP2        #
##################################
missing = 0;
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"mscorlib.dll", version:"2.0.50727.3662", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2972214");
vuln += missing;

########### KB2972207 ############
# .NET Framework 1.1 SP1         #
# Windows Server 2003 SP2        #
##################################
missing = 0;
missing += hotfix_is_vulnerable(os:"5.2", arch:"x86", sp:2, file:"mscorlib.dll", version:"1.1.4322.2510", min_version:"1.1.4322.2000", dir:"\Microsoft.NET\Framework\v1.1.4322");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2972207");
vuln += missing;

if(vuln > 0)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, "affected");
}
