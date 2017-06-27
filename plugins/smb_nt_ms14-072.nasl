#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79132);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2014-4149");
  script_bugtraq_id(70979);
  script_osvdb_id(114536);
  script_xref(name:"MSFT", value:"MS14-072");
  script_xref(name:"IAVA", value:"2014-A-0173");

  script_name(english:"MS14-072: Vulnerability in .NET Framework Could Allow Elevation of Privilege (3005210)");
  script_summary(english:"Checks the version of the .NET files.");

  script_set_attribute(attribute:"synopsis", value:
"The version of the .NET Framework installed on the remote host is
affected by a privilege elevation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of the Microsoft .NET Framework
that is affected by a vulnerability related to how it handles
TypeFilterLevel checks for some malformed objects. This can be used by
a remote attacker to gain privilege elevation via a specially crafted
packet sent to a host that is using .NET Remoting.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS14-072");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for .NET Framework 1.1 SP1,
2.0 SP2, 3.5, 3.5.1, 4.0, 4.5, 4.5.1, and 4.5.2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");

  script_set_attribute(attribute:"stig_severity", value:"I");
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

bulletin = 'MS14-072';
kbs = make_list(
  "2978114",
  "2978116",
  "2978120",
  "2978121",
  "2978122",
  "2978124",
  "2978125",
  "2978126",
  "2978127",
  "2978128"
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
# Some of the 2k3 checks could flag XP 64, which is unsupported
if ("Windows XP" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

# Determine if .NET 4.5, 4.5.1, or 4.5.2 is installed
dotnet_452_installed = FALSE;
dotnet_451_installed = FALSE;
dotnet_45_installed  = FALSE;

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
vuln = 0;

########## KB 2978114 #############
# .NET Framework 1.1 SP1          #
# Windows Server 2003 SP2         #
###################################
missing = 0;
# LDR / GDR are the same
missing += hotfix_is_vulnerable(os:"5.2", arch:"x86", sp:2, file:"mscorlib.dll", version:"1.1.4322.2511", min_version:"1.1.4322.2000", dir:"\Microsoft.NET\Framework\v1.1.4322");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2978114");
vuln += missing;

########## KB 2978116 #############
# .NET Framework 2.0 SP2         #
# Windows Vista SP2              #
# Windows Server 2008 SP2        #
##################################
missing = 0;
# GDR
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.runtime.remoting.dll", version:"2.0.50727.4255", min_version:"2.0.50727.2000", dir:"\Microsoft.NET\Framework\v2.0.50727");
# LDR
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.runtime.remoting.dll", version:"2.0.50727.8641", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2978116");
vuln += missing;

########### KB 2978120 ############
# .NET Framework 3.5.1            #
# Windows 7 SP1                   #
# Windows Server 2008 R2 SP1      #
############################$######
missing = 0;
# GDR
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.runtime.remoting.dll", version:"2.0.50727.5488", min_version:"2.0.50727.5000",  dir:"\Microsoft.NET\Framework\v2.0.50727");
# LDR
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.runtime.remoting.dll", version:"2.0.50727.8641", min_version:"2.0.50727.7000",  dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2978120");
vuln += missing;


########## KB 2978121 ###########
# .NET Framework 3.5            #
# Windows 8                     #
# Windows Server 2012           #
#################################
missing = 0;
# GDR
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.runtime.remoting.dll", version:"2.0.50727.6424", min_version:"2.0.50727.0", dir:"\Microsoft.NET\Framework\v2.0.50727");
# LDR
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.runtime.remoting.dll", version:"2.0.50727.8641", min_version:"2.0.50727.7000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2978121");
vuln += missing;

########### KB 2978122 ############
# .NET Framework 3.5              #
# Windows 8.1                     #
# Windows Server 2012 R2          #
###################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.runtime.remoting.dll", version:"2.0.50727.8012", min_version:"2.0.50727.0",  dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.runtime.remoting.dll", version:"2.0.50727.8641", min_version:"2.0.50727.8600",  dir:"\Microsoft.NET\Framework\v2.0.50727");
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2978122");
vuln += missing;

########### KB 2978124 ############
# .NET Framework 2.0 SP2          #
# Windows Server 2003 SP2         #
###################################
missing = 0;
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Runtime.Remoting.dll", version:"2.0.50727.3664", min_version:"2.0.50727.0", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Runtime.Remoting.dll", version:"2.0.50727.8642", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2978124");
vuln += missing;

########### KB 2978125 ############
# .NET Framework 4                #
# Windows Vista SP2               #
# Windows Server 2008 SP2         #
# Windows 7 SP1                   #
# Windows Server 2008 R2 SP1      #
# Windows Server 2003 SP2         #
###################################
missing = 0;

# Windows Server 2003 SP2
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Runtime.Remoting.dll", version:"4.0.30319.1030", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Runtime.Remoting.dll", version:"4.0.30319.2049", min_version:"4.0.30319.2000", dir:"\Microsoft.NET\Framework\v4.0.30319");

# Windows Vista/Server 2008 SP2
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Runtime.Remoting.dll", version:"4.0.30319.1030", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Runtime.Remoting.dll", version:"4.0.30319.2049", min_version:"4.0.30319.2000", dir:"\Microsoft.NET\Framework\v4.0.30319");

# Windows 7/Server 2008 R2 SP1
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Runtime.Remoting.dll", version:"4.0.30319.1030", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Runtime.Remoting.dll", version:"4.0.30319.2049", min_version:"4.0.30319.2000", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2978125");
vuln += missing;

########### KB 2978126 ############
# .NET Framework 4.5.1/4.5.2      #
# Windows 8.1                     #
# Windows 8.1 RT                  #
# Windows Server 2012 R2          #
###################################
missing = 0;
if (dotnet_451_installed || dotnet_452_installed)
{
  # GDR
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.runtime.remoting.dll", version:"4.0.30319.34243", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # LDR
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.runtime.remoting.dll", version:"4.0.30319.36255", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2978126");
vuln += missing;

########## KB 2978127 #############
# .NET Framework 4.5/4.5.1/4.5.2  #
# Windows 8                       #
# Windows RT                      #
# Windows Server 2012             #
###################################
if (dotnet_45_installed || dotnet_451_installed || dotnet_452_installed)
{
  missing = 0;
  # GDR
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.runtime.remoting.dll", version:"4.0.30319.34243", min_version:"4.0.30319.0", path:"\Microsoft.NET\Framework\v4.0.30319");
  # LDR
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.runtime.remoting.dll", version:"4.0.30319.36255", min_version:"4.0.30319.35000", path:"\Microsoft.NET\Framework\v4.0.30319");
  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2978127");
  vuln += missing;
}

########### KB 2978128 ############
# .NET Framework 4.5/4.5.1/4.5.2  #
# Windows Vista SP2               #
# Windows Server 2008 SP2         #
# Windows 7 SP1                   #
# Windows Server 2008 R2 SP1      #
###################################
missing = 0;
if (dotnet_45_installed || dotnet_451_installed || dotnet_452_installed)
{
  # Windows Vista/Server 2008 SP2
  # GDR
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Runtime.Remoting.dll", version:"4.0.30319.34245", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # LDR
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Runtime.Remoting.dll", version:"4.0.30319.36257", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # Windows 7/Server 2008 R2 SP1
  # GDR
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Runtime.Remoting.dll", version:"4.0.30319.34245", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # LDR
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Runtime.Remoting.dll", version:"4.0.30319.36257", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2978128");
vuln += missing;

# Report
if (vuln > 0)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, "affected");
}
