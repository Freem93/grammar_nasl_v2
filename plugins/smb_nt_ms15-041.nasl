#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82777);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/01/15 21:14:37 $");

  script_cve_id("CVE-2015-1648");
  script_bugtraq_id(74010);
  script_osvdb_id(120638);
  script_xref(name:"MSFT", value:"MS15-041");
  script_xref(name:"IAVA", value:"2015-A-0089");

  script_name(english:"MS15-041: Vulnerability in .NET Framework Could Allow Information Disclosure (3048010)");
  script_summary(english:"Checks the version of the .NET files.");

  script_set_attribute(attribute:"synopsis", value:
"The version of the Microsoft .NET Framework installed on the remote
host is affected by an information disclose vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of the Microsoft .NET Framework
installed that is affected by an information disclosure vulnerability
due to improper handling of requests on web servers that have custom
error messages disabled. A remote, unauthenticated attacker can
exploit this issue, via a specially crafted web request, to elicit an
error message containing information that was not intended to be
accessible.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-041");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for .NET Framework 1.1 SP1,
2.0 SP2, 3.5, 3.5.1, 4.0, 4.5, 4.5.1, and 4.5.2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");

  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS15-041';
kbs = make_list(
  "3037572",
  "3037573",
  "3037574",
  "3037575",
  "3037576",
  "3037577",
  "3037578",
  "3037579",
  "3037580",
  "3037581"
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

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

########## KB 3037572 #############
# .NET Framework 1.1 SP1          #
# Windows Server 2003 SP2         #
###################################
missing = 0;
# LDR / GDR are the same
missing += hotfix_is_vulnerable(os:"5.2", arch:"x86", sp:2, file:"System.Web.dll", version:"1.1.4322.2515", min_version:"1.1.4322.2000", dir:"\Microsoft.NET\Framework\v1.1.4322");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3037572");
vuln += missing;

########## KB 3037573 #############
# .NET Framework 2.0 SP2         #
# Windows Vista SP2              #
# Windows Server 2008 SP2        #
##################################
missing = 0;
# GDR
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Web.dll", version:"2.0.50727.4257", min_version:"2.0.50727.2000", dir:"\Microsoft.NET\Framework\v2.0.50727");
# LDR
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Web.dll", version:"2.0.50727.8653", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3037573");
vuln += missing;

########### KB 3037574 ############
# .NET Framework 3.5.1            #
# Windows 7 SP1                   #
# Windows Server 2008 R2 SP1      #
############################$######
missing = 0;
# GDR
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Web.dll", version:"2.0.50727.5491", min_version:"2.0.50727.5000",  dir:"\Microsoft.NET\Framework\v2.0.50727");
# LDR
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Web.dll", version:"2.0.50727.8653", min_version:"2.0.50727.7000",  dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3037574");
vuln += missing;


########## KB 3037575 ###########
# .NET Framework 3.5            #
# Windows 8                     #
# Windows Server 2012           #
#################################
missing = 0;
# GDR
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.Web.dll", version:"2.0.50727.6427", min_version:"2.0.50727.0", dir:"\Microsoft.NET\Framework\v2.0.50727");
# LDR
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.Web.dll", version:"2.0.50727.8653", min_version:"2.0.50727.7000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3037575");
vuln += missing;

########### KB 3037576 ############
# .NET Framework 3.5              #
# Windows 8.1                     #
# Windows Server 2012 R2          #
###################################
missing = 0;

missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:" System.Web.resources.dll", version:"2.0.50727.7905", min_version:"2.0.50727.6000",  dir:"\Microsoft.NET\Framework\v2.0.50727");
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3037576");
vuln += missing;

########### KB 3037577 ############
# .NET Framework 2.0 SP2          #
# Windows Server 2003 SP2         #
###################################
missing = 0;
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Web.dll", version:"2.0.50727.3668", min_version:"2.0.50727.0", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Web.dll", version:"2.0.50727.8656", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3037577");
vuln += missing;

########### KB 3037578 ############
# .NET Framework 4                #
# Windows Vista SP2               #
# Windows Server 2008 SP2         #
# Windows 7 SP1                   #
# Windows Server 2008 R2 SP1      #
# Windows Server 2003 SP2         #
###################################
missing = 0;

# Windows Server 2003 SP2
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Web.dll", version:"4.0.30319.1031", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Web.dll", version:"4.0.30319.2056", min_version:"4.0.30319.2000", dir:"\Microsoft.NET\Framework\v4.0.30319");

# Windows Vista/Server 2008 SP2
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Web.dll", version:"4.0.30319.1031", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Web.dll", version:"4.0.30319.2056", min_version:"4.0.30319.2000", dir:"\Microsoft.NET\Framework\v4.0.30319");

# Windows 7/Server 2008 R2 SP1
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Web.dll", version:"4.0.30319.1031", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Web.dll", version:"4.0.30319.2056", min_version:"4.0.30319.2000", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3037578");
vuln += missing;

########### KB 3037579 ############
# .NET Framework 4.5.1/4.5.2      #
# Windows 8.1                     #
# Windows 8.1 RT                  #
# Windows Server 2012 R2          #
###################################
missing = 0;
if (dotnet_451_installed || dotnet_452_installed)
{
  # GDR
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"System.Web.dll", version:"4.0.30319.34248", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # LDR
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"System.Web.dll", version:"4.0.30319.36283", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3037579");
vuln += missing;

########## KB 3037580 #############
# .NET Framework 4.5/4.5.1/4.5.2  #
# Windows 8                       #
# Windows RT                      #
# Windows Server 2012             #
###################################
if (dotnet_45_installed || dotnet_451_installed || dotnet_452_installed)
{
  missing = 0;
  # GDR
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.Web.dll", version:"4.0.30319.34248", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # LDR
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.Web.dll", version:"4.0.30319.36283", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3037580");
  vuln += missing;
}

########### KB 3037581 ############
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
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Web.dll", version:"4.0.30319.34249", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # LDR
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Web.dll", version:"4.0.30319.36285", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # Windows 7/Server 2008 R2 SP1
  # GDR
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Web.dll", version:"4.0.30319.34249", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # LDR
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Web.dll", version:"4.0.30319.36285", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3037581");
vuln += missing;

# Report
if (vuln > 0)
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
