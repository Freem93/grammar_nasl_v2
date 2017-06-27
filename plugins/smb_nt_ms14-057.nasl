#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78432);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2014-4073", "CVE-2014-4121", "CVE-2014-4122");
  script_bugtraq_id(70312, 70313, 70351);
  script_osvdb_id(113181, 113185, 113184);
  script_xref(name:"MSFT", value:"MS14-057");

  script_name(english:"MS14-057: Vulnerabilities in .NET Framework Could Allow Remote Code Execution (3000414)");
  script_summary(english:"Checks the version of the .NET files.");

  script_set_attribute(attribute:"synopsis", value:
"The version of the .NET Framework installed on the remote host is
affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of the Microsoft .NET Framework
that is affected by a vulnerability that allows a remote attacker to
to execute code remotely.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS14-057");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for .NET Framework 2.0 SP2,
3.5, 3.5.1, 4.0, 4.5, 4.5.1, and 4.5.2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/15");

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

bulletin = 'MS14-057';
kbs = make_list(
  "2968292",
  "2968294",
  "2968295",
  "2968296",
  "2972098",
  "2972100",
  "2972101",
  "2972103",
  "2972105",
  "2972106",
  "2972107",
  "2978041",
  "2978042",
  "2979568",
  "2979570",
  "2979571",
  "2979573",
  "2979574",
  "2979575",
  "2979576",
  "2979577",
  "2979578"
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

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

########## KB2968292 #############
# .NET Framework 2.0 SP2         #
# Windows Vista SP2              #
# Windows Server 2008 SP2        #
##################################
missing = 0;
# LDR / GDR are the same
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"mscories.dll", version:"2.0.50727.4252", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2968292");
vuln += missing;

########### KB2968294 ############
# .NET Framework 3.5.1           #
# Windows 7 SP1                  #
# Windows Server 2008 R2 SP1     #
##################################
missing = 0;
# LDR / GDR are the same
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"mscories.dll", version:"2.0.50727.5483", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2968294");
vuln += missing;

########### KB2968295 ############
# .NET Framework 3.5             #
# Windows 8                      #
# Windows Server 2012            #
##################################
missing = 0;
# LDR / GDR are the same
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"mscorie.dll", version:"2.0.50727.6419", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2968295");
vuln += missing;


########### KB2968296 ############
# .NET Framework 3.5             #
# Windows 8.1                    #
# Windows Server 2012 R2         #
##################################
missing = 0;
# LDR / GDR are the same
missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"mscorie.dll", version:"2.0.50727.8008", min_version:"2.0.50727.5000",  dir:"\Microsoft.NET\Framework\v2.0.50727");
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2968296");
vuln += missing;


########## KB2972098 #############
# .NET Framework 2.0 SP2         #
# Windows Vista SP2              #
# Windows Server 2008 SP2        #
##################################
missing = 0;
# GDR
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.dll", version:"2.0.50727.4253", min_version:"2.0.50727.2000", dir:"\Microsoft.NET\Framework\v2.0.50727");
# LDR
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.dll", version:"2.0.50727.7071", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2972098");
vuln += missing;

########### KB2972100 ############
# .NET Framework 3.5.1           #
# Windows 7 SP1                  #
# Windows Server 2008 R2 SP1     #
##################################
missing = 0;
# GDR
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.dll", version:"2.0.50727.5485", min_version:"2.0.50727.3000",  dir:"\Microsoft.NET\Framework\v2.0.50727");
# LDR
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.dll", version:"2.0.50727.7071", min_version:"2.0.50727.6000",  dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2972100");
vuln += missing;


########## KB2972101 ###########
# .NET Framework 3.5           #
# Windows 8                    #
# Windows Server 2012          #
################################
missing = 0;
# GDR
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.dll", version:"2.0.50727.6421", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");
# LDR
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.dll", version:"2.0.50727.7071", min_version:"2.0.50727.6500", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2972101");
vuln += missing;

########## KB2972103 ###########
# .NET Framework 3.5           #
# Windows 8.1                  #
# Windows Server 2012 R2       #
################################
missing = 0;
# GDR
missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.dll", version:"2.0.50727.8009", min_version:"2.0.50727.6000", dir:"\Microsoft.NET\Framework\v2.0.50727");
# LDR
missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.dll", version:"2.0.50727.8615", min_version:"2.0.50727.8100", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2972103");
vuln += missing;


########### KB2972105 ############
# .NET Framework 2.0 SP2         #
# Windows Server 2003 SP2        #
##################################
missing = 0;
# GDR
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.dll", version:"2.0.50727.3662", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");
# LDR
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.dll", version:"2.0.50727.8637", min_version:"2.0.50727.8000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2972105");
vuln += missing;


########### KB2972106 ############
# .NET Framework 4               #
# Windows Vista SP2              #
# Windows Server 2008 SP2        #
# Windows 7 SP1                  #
# Windows Server 2008 R2 SP1     #
# Windows Server 2003 SP2        #
##################################
missing = 0;

# Windows Server 2003 SP2
# GDR
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.dll", version:"4.0.30319.1026", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
# LDR
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.dll", version:"4.0.30319.2045", min_version:"4.0.30319.1500", dir:"\Microsoft.NET\Framework\v4.0.30319");

# Windows Vista/Server 2008 SP2
# GDR
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.dll", version:"4.0.30319.1026", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
# LDR
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.dll", version:"4.0.30319.2045", min_version:"4.0.30319.1500", dir:"\Microsoft.NET\Framework\v4.0.30319");

# Windows 7/Server 2008 R2 SP1
# GDR
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.dll", version:"4.0.30319.1026", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
# LDR
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.dll", version:"4.0.30319.2045", min_version:"4.0.30319.1500", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2972106");
vuln += missing;

########### KB2972107 ############
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
  # GDR
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.dll", version:"4.0.30319.34238", min_version:"4.0.30319.18000", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # LDR
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.dll", version:"4.0.30319.36250", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # Windows 7/Server 2008 R2 SP1
  # GDR
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.dll", version:"4.0.30319.34238", min_version:"4.0.30319.18000", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # LDR
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.dll", version:"4.0.30319.36250", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2972107");
vuln += missing;

########### KB2978041 ############
# .NET Framework 4.5.1/4.5.2     #
# Windows 8.1                    #
# Windows 8.1 RT                 #
# Windows Server 2012 R2         #
##################################
missing = 0;
if (dotnet_451_installed || dotnet_452_installed)
{
  # GDR
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.resources.dll", version:"4.0.30319.34209", min_version:"4.0.30319.18000", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # LDR
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.resources.dll", version:"4.0.30319.36213", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2978041");
vuln += missing;

########## KB2978042 #############
# .NET Framework 4.5/4.5.1/4.5.2 #
# Windows 8                      #
# Windows RT                     #
# Windows Server 2012            #
##################################
if (dotnet_45_installed || dotnet_451_installed || dotnet_452_installed)
{
  missing = 0;
  # GDR
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.resources.dll", version:"4.0.30319.34209", min_version:" 4.0.30319.18000", path:"\Microsoft.NET\Framework\v4.0.30319");
  # LDR
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.resources.dll", version:"4.0.30319.36213", min_version:" 4.0.30319.35000", path:"\Microsoft.NET\Framework\v4.0.30319");
  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2978042");
  vuln += missing;
}

########## KB2979568 #############
# .NET Framework 2.0 SP2         #
# Windows Vista SP2              #
# Windows Server 2008 SP2        #
##################################
missing = 0;
# GDR
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"dfdll.dll", version:"2.0.50727.4255", min_version:"2.0.50727.2000", dir:"\Microsoft.NET\Framework\v2.0.50727");
# LDR
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"dfdll.dll", version:"2.0.50727.8641", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2979568");
vuln += missing;

########### KB2979570 ############
# .NET Framework 3.5.1           #
# Windows 7 SP1                  #
# Windows Server 2008 R2 SP1     #
##################################
missing = 0;
# GDR
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"dfdll.dll", version:"2.0.50727.5488", min_version:"2.0.50727.2000", dir:"\Microsoft.NET\Framework\v2.0.50727");
# LDR
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"dfdll.dll", version:"2.0.50727.8641", min_version:"2.0.50727.6500", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2979570");
vuln += missing;


########## KB2979571 ###########
# .NET Framework 3.5           #
# Windows 8                    #
# Windows Server 2012          #
################################
missing = 0;
# GDR
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"dfdll.dll", version:"2.0.50727.6424", min_version:"2.0.50727.2000", dir:"\Microsoft.NET\Framework\v2.0.50727");
# LDR
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"dfdll.dll", version:"2.0.50727.8641", min_version:"2.0.50727.6500", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2979571");
vuln += missing;


########## KB2979573 ##############
# .NET Framework 3.5              #
# Windows 8.1                     #
# Windows Server 2012 R2          #
###################################
missing = 0;
# LDR
missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"dfdll.dll", version:"2.0.50727.8641", min_version:"2.0.50727.8100",  dir:"\Microsoft.NET\Framework\v2.0.50727");
# GDR
missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"dfdll.dll", version:"2.0.50727.8012", min_version:"2.0.50727.4000",  dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2979573");
vuln += missing;

########### KB2979574 ############
# .NET Framework 2.0 SP2         #
# Windows Server 2003 SP2        #
##################################
missing = 0;
# GDR
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Deployment.dll", version:"2.0.50727.3663", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");
# LDR
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Deployment.dll", version:"2.0.50727.8641", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2979574");
vuln += missing;

########### KB2979575 ############
# .NET Framework 4               #
# Windows Vista SP2              #
# Windows Server 2008 SP2        #
# Windows 7 SP1                  #
# Windows Server 2008 R2 SP1     #
# Windows Server 2003 SP2        #
##################################
missing = 0;

# Windows Server 2003 SP2
# GDR
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Deployment.dll", version:"4.0.30319.1029", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
# LDR
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Deployment.dll", version:"4.0.30319.2048", min_version:"4.0.30319.1500", dir:"\Microsoft.NET\Framework\v4.0.30319");

# Windows Vista/Server 2008 SP2
# GDR
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Deployment.dll", version:"4.0.30319.1029", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
# LDR
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Deployment.dll", version:"4.0.30319.2048", min_version:"4.0.30319.1500", dir:"\Microsoft.NET\Framework\v4.0.30319");

# Windows 7/Server 2008 R2 SP1
# GDR
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Deployment.dll", version:"4.0.30319.1029", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
# LDR
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Deployment.dll", version:"4.0.30319.2048", min_version:"4.0.30319.1500", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2979575");
vuln += missing;

########### KB2979576 ############
# .NET Framework 4.5.1/4.5.2     #
# Windows 8.1                    #
# Windows 8.1 RT                 #
# Windows Server 2012 R2         #
##################################
missing = 0;
if (dotnet_451_installed || dotnet_452_installed)
{
  # GDR
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.deployment.dll", version:"4.0.30319.34243", min_version:"4.0.30319.10000", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # LDR
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.deployment.dll", version:"4.0.30319.36255", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2979576");
vuln += missing;

########## KB2979577 #############
# .NET Framework 4.5/4.5.1/4.5.2 #
# Windows 8.1                    #
# Windows RT                     #
# Windows Server 2012 R2         #
##################################
if (dotnet_45_installed || dotnet_451_installed || dotnet_452_installed)
{
  missing = 0;
  # GDR
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.deployment.dll", version:"4.0.30319.34243", min_version:"4.0.30319.10000", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # LDR
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.deployment.dll", version:"4.0.30319.36255", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2979577");
  vuln += missing;
}

########### KB2979578 ############
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
  # GDR
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Deployment.dll", version:"4.0.30319.34244", min_version:"4.0.30319.18000", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # LDR
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Deployment.dll", version:"4.0.30319.36256", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # Windows 7/Server 2008 R2 SP1
  # GDR
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Deployment.dll", version:"4.0.30319.34244", min_version:"4.0.30319.18000", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # LDR
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Deployment.dll", version:"4.0.30319.36256", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2979578");
vuln += missing;

# Report
if(vuln > 0)
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
