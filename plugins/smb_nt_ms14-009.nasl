#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(72432);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2014-0253", "CVE-2014-0257", "CVE-2014-0295");
  script_bugtraq_id(65415, 65417, 65418);
  script_osvdb_id(103162, 103163, 103164);
  script_xref(name:"MSFT", value:"MS14-009");

  script_name(english:"MS14-009: Vulnerabilities in .NET Framework Could Allow Privilege Escalation (2916607)");
  script_summary(english:"Checks version of System.Security.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of the .NET Framework installed on the remote host is
affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host is running a version of the Microsoft .NET
Framework that is affected by multiple vulnerabilities :

  - An error exists related to handling stale or closed
    HTTP client connections that can allow denial of service
    attacks. (CVE-2014-0253)

  - An error exists related to decisions regarding the
    safety of executing certain methods that can allow
    privilege escalation. (CVE-2014-0257)

  - An error exists related to the component 'VSAVB7RT'
    that can allow Address Space Layout Randomization (ASLR)
    bypasses. (CVE-2014-0295)"
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS14-009");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for .NET Framework 1.1 SP1, 2.0
SP2, 3.5, 3.5.1, 4.0, 4.5, and 4.5.1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS14-009 .NET Deployment Service IE Sandbox Escape');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/12");

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
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");
include("smb_reg_query.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS14-009';
kbs = make_list(
  "2898855",
  "2898856",
  "2898857",
  "2898858",
  "2898860",
  "2898864",
  "2898865",
  "2898866",
  "2898868",
  "2898869",
  "2898870",
  "2898871",
  "2901110",
  "2901111",
  "2901112",
  "2901113",
  "2901115",
  "2901118",
  "2901119",
  "2901120",
  "2901125",
  "2901126",
  "2901127",
  "2901128",
# "2904878", # Not checked
             # Media Center Edition 2005 Service Pack 3 and Tablet PC Edition 2005 Service Pack 3 only
  "2911501",
  "2911502"
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

# Determine if .NET 4.5 or 4.5.1 is installed
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
  }
}
vuln = 0;

########## KB2898855 ###########
#  .NET Framework 4.0          #
#  Windows XP SP3,             #
#  Windows XP SP2 x64,         #
#  Windows 2003 SP2,           #
#  Windows Vista SP2,          #
#  Windows 7 SP1,              #
#  Windows Server 2008 SP2,    #
#  Windows Server 2008 R2 SP1  #
################################
missing = 0;
# Windows XP SP3
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"mscorlib.dll", version:"4.0.30319.1022", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"mscorlib.dll", version:"4.0.30319.2034", min_version:"4.0.30319.1200", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Windows XP SP2 x64 / Server 2003 SP2
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"mscorlib.dll", version:"4.0.30319.1022", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"mscorlib.dll", version:"4.0.30319.2034", min_version:"4.0.30319.1200", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Windows Vista SP2 / Server 2008 SP2
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"mscorlib.dll", version:"4.0.30319.1022", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"mscorlib.dll", version:"4.0.30319.2034", min_version:"4.0.30319.1200", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Windows 7 SP1 / 2008 R2 SP1
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"mscorlib.dll", version:"4.0.30319.1022", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"mscorlib.dll", version:"4.0.30319.2034", min_version:"4.0.30319.1200", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2898855");
vuln += missing;

######### KB2898856 ############
#  .NET Framework 2.0 SP2     #
#  Windows XP SP 3,           #
#  Server 2003 SP2            #
###############################
missing = 0;
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"mscorlib.dll", version:"2.0.50727.7041", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"mscorlib.dll", version:"2.0.50727.3655", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"mscorlib.dll", version:"2.0.50727.7041", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"mscorlib.dll", version:"2.0.50727.3655", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2898856");
vuln += missing;

########## KB2898857 ############
#  .NET Framework 3.5.1        #
#  Windows 7 SP1,              #
#  Server 2008 R2 SP1          #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"mscorlib.dll", version:"2.0.50727.7041", min_version:"2.0.50727.5600", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"mscorlib.dll", version:"2.0.50727.5477", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2898857");
vuln += missing;

########## KB2898858 ############
#  .NET Framework 2.0 SP2      #
#  Windows Vista SP2,          #
#  Server 2008 SP2             #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"mscorlib.dll", version:"2.0.50727.7041", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"mscorlib.dll", version:"2.0.50727.4247", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2898858");
vuln += missing;

########### KB2898860 ###########
#  .NET Framework 1.1 SP1      #
#  Server 2003 SP2 32-bit      #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"5.2", arch:"x86", sp:2, file:"mscorlib.dll", version:"1.1.4322.2504", min_version:"1.1.4322.2000", dir:"\Microsoft.NET\Framework\v1.1.4322");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2898860");
vuln += missing;

########### KB2898864 ###########
#  .NET Framework 4.5          #
#  Windows Vista SP2,          #
#  Server 2008 SP2             #
#  Windows 7 SP1,              #
#  Server 2008 R2 SP1          #
################################
missing = 0;
if (dotnet_45_installed)
{
  # Vista SP2 / 2008 SP2
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"mscorlib.dll", version:"4.0.30319.18063", min_version:"4.0.30319.18000", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"mscorlib.dll", version:"4.0.30319.19132", min_version:"4.0.30319.19000", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # 7 / 2008 R2 SP1
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"mscorlib.dll", version:"4.0.30319.18063", min_version:"4.0.30319.18000", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"mscorlib.dll", version:"4.0.30319.19132", min_version:"4.0.30319.19000", dir:"\Microsoft.NET\Framework\v4.0.30319");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2898864");
vuln += missing;

########## KB2898865 ############
#  .NET Framework 4.5          #
#  Windows 8,                  #
#  Server 2012                 #
################################
missing = 0;
if (dotnet_45_installed)
{
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"mscorlib.dll", version:"4.0.30319.18449", min_version:"4.0.30319.18400", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"mscorlib.dll", version:"4.0.30319.19455", min_version:"4.0.30319.19400", dir:"\Microsoft.NET\Framework\v4.0.30319");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2898865");
vuln += missing;

########## KB2898866 ############
#  .NET Framework 3.5          #
#  Windows 8,                  #
#  Server 2012                 #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"mscorlib.dll", version:"2.0.50727.6413", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"mscorlib.dll", version:"2.0.50727.7041", min_version:"2.0.50727.7000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2898866");
vuln += missing;

########## KB2898868 ############
#  .NET Framework 3.5          #
#  Windows 8.1,                #
#  Server 2012 R2              #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"mscorlib.dll", version:"2.0.50727.8000", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2898868");
vuln += missing;

########## KB2898869 ############
#  .NET Framework 4.5.1        #
#  Windows Vista SP2,          #
#  Server 2008 SP2             #
#  Windows 7 SP1,              #
#  Server 2008 R2 SP1          #
################################
missing = 0;
if (dotnet_451_installed)
{
  # Vista SP2 / 2008 SP2
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"mscorlib.dll", version:"4.0.30319.18444", min_version:"4.0.30319.18400", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # 7 / 2008 R2 SP1
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"mscorlib.dll", version:"4.0.30319.18444", min_version:"4.0.30319.18400", dir:"\Microsoft.NET\Framework\v4.0.30319");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2898869");
vuln += missing;

########## KB2898870 ############
#  .NET Framework 4.5.1        #
#  Windows 8,                  #
#  Server 2012                 #
################################
missing = 0;
if (dotnet_451_installed)
{
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"mscorlib.dll", version:"4.0.30319.18449", min_version:"4.0.30319.18400", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"mscorlib.dll", version:"4.0.30319.19455", min_version:"4.0.30319.19400", dir:"\Microsoft.NET\Framework\v4.0.30319");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2898870");
vuln += missing;

########## KB2898871 ############
#  .NET Framework 4.5.1        #
#  Windows 8.1,                #
#  Server 2012 R2              #
################################
missing = 0;
if (dotnet_451_installed)
{
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"mscorlib.dll", version:"4.0.30319.34011", min_version:"4.0.30319.34000", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"mscorlib.dll", version:"4.0.30319.36013", min_version:"4.0.30319.36000", dir:"\Microsoft.NET\Framework\v4.0.30319");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2898871");
vuln += missing;

########## KB2901110 ############
#  .NET Framework 4.0          #
#  Windows XP SP3,             #
#  Windows XP SP2 x64,         #
#  Windows 2003 SP2,           #
#  Windows Vista SP2,          #
#  Windows 7 SP1,              #
#  Windows Server 2008 SP2,    #
#  Windows Server 2008 R2 SP1  #
################################
missing = 0;
# Windows XP SP3
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.Web.dll", version:"4.0.30319.1022", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.Web.dll", version:"4.0.30319.2034", min_version:"4.0.30319.1200", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Windows XP SP2 x64 / Server 2003 SP2
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Web.dll", version:"4.0.30319.1022", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Web.dll", version:"4.0.30319.2034", min_version:"4.0.30319.1200", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Windows Vista SP2 / Server 2008 SP2
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Web.dll", version:"4.0.30319.1022", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Web.dll", version:"4.0.30319.2034", min_version:"4.0.30319.1200", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Windows 7 SP1 / 2008 R2 SP1
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Web.dll", version:"4.0.30319.1022", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Web.dll", version:"4.0.30319.2034", min_version:"4.0.30319.1200", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2901110");
vuln += missing;

########## KB2901111 ############
#  .NET Framework 2.0 SP2      #
#  Windows XP SP 3,            #
#  Server 2003 SP2             #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.Web.dll", version:"2.0.50727.7046", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.Web.dll", version:"2.0.50727.3658", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Web.dll", version:"2.0.50727.7046", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Web.dll", version:"2.0.50727.3658", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2901111");
vuln += missing;

########## KB2901112 ############
#  .NET Framework 3.5.1        #
#  Windows 7 SP1,              #
#  Server 2008 R2 SP1          #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Web.dll", version:"2.0.50727.5479", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Web.dll", version:"2.0.50727.7045", min_version:"2.0.50727.7000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2901112");
vuln += missing;

########## KB2901113 ############
#  .NET Framework 2.0 SP2      #
#  Windows Vista SP2,          #
#  Server 2008 SP2             #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Web.dll", version:"2.0.50727.7045", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Web.dll", version:"2.0.50727.4248", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2901113");
vuln += missing;

########## KB2901115 ############
#  .NET Framework 1.1 SP1      #
#  Server 2003 SP2 32-bit      #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"5.2", arch:"x86", sp:2, file:"System.Web.dll", version:"1.1.4322.2505", min_version:"1.1.4322.2200", dir:"\Microsoft.NET\Framework\v1.1.4322");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2901115");
vuln += missing;

########## KB2901118 ############
#  .NET Framework 4.5          #
#  Windows Vista SP2,          #
#  Server 2008 SP2             #
#  Windows 7 SP1,              #
#  Server 2008 R2 SP1          #
################################
missing = 0;
if (dotnet_45_installed)
{
  # Vista SP2 / 2008 SP2
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Web.dll", version:"4.0.30319.18067", min_version:"4.0.30319.18000", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Web.dll", version:"4.0.30319.19136", min_version:"4.0.30319.19000", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # 7 / 2008 R2 SP1
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Web.dll", version:"4.0.30319.18067", min_version:"4.0.30319.18000", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Web.dll", version:"4.0.30319.19136", min_version:"4.0.30319.19000", dir:"\Microsoft.NET\Framework\v4.0.30319");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2901118");
vuln += missing;

########## KB2901119 ############
#  .NET Framework 4.5          #
#  Windows 8,                  #
#  Server 2012                 #
################################
missing = 0;
if (dotnet_45_installed)
{
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.Web.dll", version:"4.0.30319.18449", min_version:"4.0.30319.18400", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.Web.dll", version:"4.0.30319.19455", min_version:"4.0.30319.19400", dir:"\Microsoft.NET\Framework\v4.0.30319");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2901119");
vuln += missing;

########## KB2901120 ############
#  .NET Framework 3.5          #
#  Windows 8,                  #
#  Server 2012                 #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.Web.dll", version:"2.0.50727.6414", min_version:"2.0.50727.6000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.Web.dll", version:"2.0.50727.7045", min_version:"2.0.50727.7000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2901120");
vuln += missing;

########## KB2901125 ############
#  .NET Framework 3.5          #
#  Windows 8.1,                #
#  Server 2012 R2              #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"System.Web.dll", version:"2.0.50727.8001", min_version:"2.0.50727.7000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2901125");
vuln += missing;

########## KB2901126 ############
#  .NET Framework 4.5.1        #
#  Windows Vista SP2,          #
#  Server 2008 SP2             #
#  Windows 7 SP1,              #
#  Server 2008 R2 SP1          #
################################
missing = 0;
if (dotnet_451_installed)
{
  # Vista SP2 / 2008 SP2
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Web.dll", version:"4.0.30319.18446", min_version:"4.0.30319.18400", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # 7 / 2008 R2 SP1
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Web.dll", version:"4.0.30319.18446", min_version:"4.0.30319.18400", dir:"\Microsoft.NET\Framework\v4.0.30319");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2901126");
vuln += missing;

########## KB2901127 ############
#  .NET Framework 4.5.1        #
#  Windows 8,                  #
#  Server 2012                 #
################################
missing = 0;
if (dotnet_451_installed)
{
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.Web.dll", version:"4.0.30319.18447", min_version:"4.0.30319.18400", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.Web.dll", version:"4.0.30319.19453", min_version:"4.0.30319.19400", dir:"\Microsoft.NET\Framework\v4.0.30319");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2901127");
vuln += missing;

########## KB2901128 ############
#  .NET Framework 4.5.1        #
#  Windows 8.1,                #
#  Server 2012 R2              #
################################
missing = 0;
if (dotnet_451_installed)
{
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"System.Web.dll", version:"4.0.30319.34009", min_version:"4.0.30319.32009", dir:"\Microsoft.NET\Framework\v4.0.30319");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2901128");
vuln += missing;

########## KB2911501 ############
#  .NET Framework 3.5.1        #
#  Windows 7 SP1,              #
#  Server 2008 R2 SP1          #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"microsoft.vsa.vb.codedomprocessor.dll", version:"8.0.50727.5481", min_version:"8.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"microsoft.vsa.vb.codedomprocessor.dll", version:"8.0.50727.7051", min_version:"8.0.50727.7000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2911501");
vuln += missing;

########## KB2911502 ############
#  .NET Framework 2.0 SP2      #
#  Windows Vista SP2,          #
#  Server 2008 SP2             #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"microsoft.vsa.vb.codedomprocessor.dll", version:"8.0.50727.4250", min_version:"8.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"microsoft.vsa.vb.codedomprocessor.dll", version:"8.0.50727.7051", min_version:"8.0.50727.6000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2911502");
vuln += missing;

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
