#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85847);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/06 17:11:39 $");

  script_cve_id("CVE-2015-2504", "CVE-2015-2526");
  script_bugtraq_id(76560, 76567);
  script_osvdb_id(127218);
  script_xref(name:"MSFT", value:"MS15-101");
  script_xref(name:"IAVA", value:"2015-A-0213");

  script_name(english:"MS15-101: Vulnerabilities in .NET Framework Could Allow Elevation of Privilege (3089662)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The version of the .NET Framework installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple vulnerabilities in the Microsoft .NET
Framework :

  - An elevation of privilege vulnerability exists due to
    improper validation of the number of objects in memory
    before they are copied into an array. A remote,
    unauthenticated attacker can exploit this to bypass Code
    Access Security (CAS) restrictions by convincing a user
    to run an untrusted .NET application or to visit a
    website containing a malicious XAML browser application.
    (CVE-2015-2504)

  - A denial of service vulnerability exists due to improper
    handling of specially crafted requests to an ASP .NET
    server. A remote, unauthenticated attacker can exploit
    this to degrade performance. (CVE-2015-2526)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-101");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for .NET Framework 2.0, 3.5,
3.5.1, 4, 4.5, 4.5.1, 4.5.2, and 4.6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/09/08");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/08");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
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

bulletin = 'MS15-101';
kbs = make_list(
  '3074228', # .NET 4.5.1/4.5.2 Windows 8.1/2012 R2 DoS
  '3074229', # .NET 4.5/4.5.1/4.5.2 Windows 8/2012 Elevation of Privilege
  '3074230', # .NET 4.5/4.5.1/4.5.2 Vista/2008/7/2008 R2 DoS
  '3074231', # .NET 4.6 Windows 8/2012 DoS
  '3074232', # .NET 4.6 Windows 8.1/2012 R2 DoS
  '3074233', # .NET 4.6 Vista/2008/7/2008 R2 DoS
  '3074541', # .NET 2.0 SP2 Vista/2008 Elevation of Privilege
  '3074543', # .NET 3.5.1 Windows 7/2008 R2 Elevation of Privilege
  '3074544', # .NET 3.5 Windows 8/2012 Elevation of Privilege
  '3074545', # .NET 3.5 Windows 8.1/2012 R2 Elevation of Privilege
  '3074547', # .NET 4 Vista/2008/7/2008 R2 Elevation of Privilege
  '3074548', # .NET 4.5.1/4.5.2 Windows 8.1/2012 R2 Elevation of Privilege
  '3074549', # .NET 4.5/4.5.1/4.5.2 Windows 8/2012 DoS
  '3074550', # .NET 4.5/4.5.1/4.5.2 Vista/2008/7/2008 R2 Elevation of Privilege
  '3074552', # .NET 4.6 Windows 8/2012 Elevation of Privilege
  '3074553', # .NET 4.6 Windows 8.1/2012 R2 Elevation of Privilege
  '3074554', # .NET 4.6 Vista/2008/7/2008 R2 Elevation of Privilege
  '3081455'  # .NET 3.5/4.6 Windows 10 Elevation of Privilege/DoS
);


if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

# Determine if .NET 4.5, 4.5.1, 4.5.2, or 4.6 is installed
dotnet_452_installed = FALSE;
dotnet_451_installed = FALSE;
dotnet_45_installed  = FALSE;
dotnet_46_installed  = FALSE;

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
    if (ver == "4.6") dotnet_46_installed = TRUE;
  }
}

vuln = 0;

########## KB 3074228 #############
# .NET Framework 4.5.1/4.5.2      #
# Windows 8.1 / 2012 R2           #
###################################
missing = 0;

if (dotnet_451_installed || dotnet_452_installed)
{
  # GDR
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.componentmodel.dataannotations.dll", version:"4.0.30319.34262", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # LDR
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.componentmodel.dataannotations.dll", version:"4.0.30319.36305", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3074228");
vuln += missing;

########## KB 3074229 #############
# .NET Framework 4.5/4.5.1/4.5.2  #
# Windows 8 / 2012                #
###################################
missing = 0;
if (dotnet_45_installed || dotnet_451_installed || dotnet_452_installed)
{
  # GDR
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.drawing.dll", version:"4.0.30319.34262", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # LDR
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.drawing.dll", version:"4.0.30319.36305", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3074229");
  vuln += missing;
}

########## KB 3074230 #############
# .NET Framework 4.5/4.5.1/4.5.2  #
# Windows Vista/2008/7/2008 R2    #
###################################
missing = 0;
if (dotnet_45_installed || dotnet_451_installed || dotnet_452_installed)
{
  # GDR
  # Vista / 2008
   missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.ComponentModel.DataAnnotations.dll", version:"4.0.30319.34268", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # 7 / 2008 R2
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.ComponentModel.DataAnnotations.dll", version:"4.0.30319.34268", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");

  # LDR
  # Vista / 2008
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.ComponentModel.DataAnnotations.dll", version:"4.0.30319.36308", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # 7 / 2008 R2
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.ComponentModel.DataAnnotations.dll", version:"4.0.30319.36308", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3074230");
  vuln += missing;
}

############ KB 3074231 #############
#  .NET Framework 4.6/4.6 RC        #
#  Windows 8,                       #
#  Server 2012                      #
#####################################
missing = 0;
if (dotnet_46_installed)
{
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.componentmodel.dataannotations.dll", version:"4.6.93.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3074231");
  vuln += missing;
}

############ KB 3074232 #############
#  .NET Framework 4.6/4.6 RC        #
#  Windows 8.1,                     #
#  Server 2012 R2                   #
#####################################
missing = 0;
if (dotnet_46_installed)
{
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"System.componentmodel.dataannotations.dll", version:"4.6.93.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3074232");
  vuln += missing;
}

############ KB 3074233 #############
#  .NET Framework 4.6/4.6 RC        #
#  Windows Vista, 7                 #
#  Server 2008 / 2008 R2            #
#####################################
missing = 0;
if (dotnet_46_installed)
{
  # Vista / 2008
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.ComponentModel.DataAnnotations.dll", version:"4.6.103.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # 7 / 2008 R2
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.ComponentModel.DataAnnotations.dll", version:"4.6.103.0", min_version:"4.6.0.0",  dir:"\Microsoft.NET\Framework\v4.0.30319");

 if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3074233");
  vuln += missing;
}

############ KB 3074541 #############
#  .NET Framework 2.0 SP2           #
#  Windows Vista                    #
#  Server 2008                      #
#####################################
missing = 0;
# GDR
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.drawing.dll", version:"2.0.50727.4258", min_version:"2.0.50727.2000", dir:"\Microsoft.NET\Framework\v2.0.50727");
# LDR
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.drawing.dll", version:"2.0.50727.8663", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3074541");
vuln += missing;

########### KB 3074543 ############
# .NET Framework 3.5.1            #
# Windows 7                       #
# Windows Server 2008 R2          #
############################$######
missing = 0;
# GDR
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.drawing.dll", version:"2.0.50727.5492", min_version:"2.0.50727.5000",  dir:"\Microsoft.NET\Framework\v2.0.50727");
# LDR
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.drawing.dll", version:"2.0.50727.8663", min_version:"2.0.50727.7000",  dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3074543");
vuln += missing;

########## KB 3074544 ###########
# .NET Framework 3.5            #
# Windows 8                     #
# Windows Server 2012           #
#################################
missing = 0;
# GDR
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.drawing.dll", version:"2.0.50727.6428", min_version:"2.0.50727.0", dir:"\Microsoft.NET\Framework\v2.0.50727");
# LDR
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.drawing.dll", version:"2.0.50727.8663", min_version:"2.0.50727.7000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3074544");
vuln += missing;

########## KB 3074545 ###########
# .NET Framework 3.5            #
# Windows 8.1                   #
# Windows Server 2012 R2        #
#################################
missing = 0;
# GDR
missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.drawing.dll", version:"2.0.50727.8016", min_version:"2.0.50727.0", dir:"\Microsoft.NET\Framework\v2.0.50727");
# LDR
missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.drawing.dll", version:"2.0.50727.8663", min_version:"2.0.50727.8500", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3074545");
vuln += missing;

########### KB 3074547 ############
# .NET Framework 4                #
# Windows Vista / 7               #
# Windows Server 2008 / 2008 R2   #
###################################
missing = 0;
# GDR
# Vista / 2008
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Drawing.dll", version:"4.0.30319.1036", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
# 7 / 2008 R2
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Drawing.dll", version:"4.0.30319.1036", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");

# LDR
# Vista / 2008
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Drawing.dll", version:"4.0.30319.2063", min_version:"4.0.30319.1200", dir:"\Microsoft.NET\Framework\v4.0.30319");
# 7 / 2008 R2
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Drawing.dll", version:"4.0.30319.2063", min_version:"4.0.30319.1200", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3074547");
vuln += missing;

############ KB 3074548 #############
#  .NET Framework 4.5.1/4.5.2       #
#  Windows 8.1,                     #
#  Server 2012 R2                   #
#####################################
missing = 0;
if (dotnet_451_installed || dotnet_452_installed)
{
  # GDR
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.drawing.dll", version:"4.0.30319.34262", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # LDR
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.drawing.dll", version:"4.0.30319.36305", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3074548");
  vuln += missing;
}

############ KB 3074549 #############
#  .NET Framework 4.5/4.5.1/4.5.2   #
#  Windows 8,                       #
#  Server 2012                      #
#####################################
missing = 0;
if (dotnet_45_installed || dotnet_451_installed || dotnet_452_installed)
{
  # GDR
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.componentmodel.dataannotations.resources.dll", version:"4.0.30319.18010", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # LDR
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.componentmodel.dataannotations.resources.dll", version:"4.0.30319.19010", min_version:"4.0.30319.19000", dir:"\Microsoft.NET\Framework\v4.0.30319");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3074549");
  vuln += missing;
}

############ KB 3074550 #############
#  .NET Framework 4.5/4.5.1/4.5.2   #
#  Windows Vista, 7                 #
#  Server 2008 / 2008 R2            #
#####################################
missing = 0;
if (dotnet_45_installed || dotnet_451_installed || dotnet_452_installed)
{
  # GDR
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Drawing.dll", version:"4.0.30319.34270", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Drawing.dll", version:"4.0.30319.34270", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # LDR
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Drawing.dll", version:"4.0.30319.36310", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Drawing.dll", version:"4.0.30319.36310", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3074550");
  vuln += missing;
}

############ KB 3074552 #############
#  .NET Framework 4.6/4.6 RC        #
#  Windows 8,                       #
#  Server 2012                      #
#####################################
missing = 0;
if (dotnet_46_installed)
{
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.drawing.dll", version:"4.6.93.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3074552");
  vuln += missing;
}

############ KB 3074553 #############
#  .NET Framework 4.6/4.6 RC        #
#  Windows 8.1,                     #
#  Server 2012 R2                   #
#####################################
missing = 0;
if (dotnet_46_installed)
{
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"System.drawing.dll", version:"4.6.93.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3074553");
  vuln += missing;
}

############ KB 3074554 #############
#  .NET Framework 4.6/4.6 RC        #
#  Windows Vista, 7                 #
#  Server 2008 / 2008 R2            #
#####################################
missing = 0;
if (dotnet_46_installed)
{
  # Windows Vista / Server 2008
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Drawing.dll", version:"4.6.91.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # Windows 7 / Server 2008 R2
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Drawing.dll", version:"4.6.91.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3074554");
  vuln += missing;
}

############ KB 3081455 #############
#  .NET Framework 3.5/4.6/4.6 RC    #
#  Windows 10                       #
#####################################
missing = 0;
# .NET 3.5
missing += hotfix_is_vulnerable(os:"10", sp:0, file:"system.drawing.dll", version:"2.0.50727.8663", min_version:"2.0.50727.0", dir:"\Microsoft.NET\Framework\v2.0.50727");

# .NET 4.6
if (dotnet_46_installed)
{
  missing += hotfix_is_vulnerable(os:"10", sp:0, file:"system.drawing.dll", version:"4.6.93.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3081455");
vuln += missing;

# Reporting 
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
