#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86825);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/30 23:05:16 $");

  script_cve_id("CVE-2015-6096", "CVE-2015-6099", "CVE-2015-6115");
  script_bugtraq_id(77474, 77479, 77482);
  script_osvdb_id(130058, 130059, 130060);
  script_xref(name:"MSFT", value:"MS15-118");
  script_xref(name:"IAVA", value:"2015-A-0271");

  script_name(english:"MS15-118: Security Update for .NET Framework to Address Elevation of Privilege (3104507)");
  script_summary(english:"Checks the version of the .NET files.");

  script_set_attribute(attribute:"synopsis",value:
"The version of the .NET Framework installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The remote Windows host has a version of the Microsoft .NET Framework
that is affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists in the
    .NET Framework due to improper DTD parsing of crafted
    XML files. An unauthenticated, remote attacker can
    exploit this, via a malicious application file, to gain
    read access to the local files on the system.
    (CVE-2015-6096)

  - An cross-site scripting vulnerability exists in ASP.NET
    due to improper validation of values in HTTP requests.
    An unauthenticated, remote attacker can exploit this to
    inject arbitrary script into the user's browser session.
    (CVE-2015-6099)

  - A security feature bypass vulnerability exists in the
    .NET Framework due to improper implementation of the
    Address Space Layout Randomization (ASLR) feature. An
    unauthenticated, remote attacker can exploit this, via
    crafted website content, to predict memory offsets in
    a call stack. (CVE-2015-6115)");
  script_set_attribute(attribute:"see_also",value:"https://technet.microsoft.com/library/security/MS15-118");
  script_set_attribute(attribute:"solution",value:
"Microsoft has released a set of patches for .NET Framework 2.0 SP2,
3.5, 3.5.1, 4.0, 4.5, 4.5.1, 4.5.2, and 4.6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/11/10");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/10");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

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

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS15-118';
kbs = make_list(
  "3097988",
  "3097989",
  "3097991",
  "3097992",
  "3097994",
  "3097995",
  "3097996",
  "3097997",
  "3097999",
  "3098000",
  "3098001",
  "3098778",
  "3098779",
  "3098780",
  "3098781",
  "3098784",
  "3098785",
  "3098786",
  "3105213"
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

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

############ KB3098785 #############
#  .NET Framework 4.6/4.6 RC       #
#  Windows 8.1,                    #
#  Server 2012 R2                  #
####################################
missing = 0;
if (dotnet_46_installed)
{
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"System.web.dll", version:"4.6.114.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3098785");
  vuln += missing;
}

############ KB3098000 ##############
#  .NET Framework 4.6/4.6 RC        #
#  Windows 8.1,                     #
#  Server 2012 R2                   #
#####################################
missing = 0;
if (dotnet_46_installed)
{
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"Dfdll.dll", version:"4.6.114.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3098000");
  vuln += missing;
}

########## KB3098779 ############
#  .NET Framework 4.5.1 / 4.5.2 #
#  Windows 8.1,                 #
#  Server 2012 R2               #
#################################
missing = 0;
if (dotnet_451_installed || dotnet_452_installed)
{
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"System.web.dll", version:"4.0.30319.34274", min_version:"4.0.30319.18000", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"System.web.dll", version:"4.0.30319.36323", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3098779");
vuln += missing;

############# KB3098784 #############
#  .NET Framework 4.6/4.6 RC        #
#  Windows 8,                       #
#  Server 2012                      #
#####################################
missing = 0;
if (dotnet_46_installed)
{
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.web.dll", version:"4.6.114.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3098784");
  vuln += missing;
}

############# KB3097999 #############
#  .NET Framework 4.6/4.6 RC        #
#  Windows 8,                       #
#  Server 2012                      #
#####################################
missing = 0;
if (dotnet_46_installed)
{
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"Dfdll.dll", version:"4.6.114.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3097999");
  vuln += missing;
}

########## KB3098780 ###########
#  .NET Framework 4.5.1        #
#  Windows 8,                  #
#  Server 2012                 #
################################
missing = 0;
if (dotnet_45_installed || dotnet_451_installed || dotnet_452_installed)
{
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.web.dll", version:"4.0.30319.34274", min_version:"4.0.30319.18000", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.web.dll", version:"4.0.30319.36323", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3098780");
vuln += missing;

########## KB3097995 ###########
#  .NET Framework 4.5.1        #
#  Windows 8,                  #
#  Server 2012                 #
################################
missing = 0;
if (dotnet_45_installed || dotnet_451_installed || dotnet_452_installed)
{
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"dfdll.dll", version:"4.0.30319.34274", min_version:"4.0.30319.18000", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"dfdll.dll", version:"4.0.30319.36323", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3097995");
vuln += missing;

############# KB3098001 #############
#  .NET Framework 4.6/4.6 RC        #
#  Windows Vista, 7                 #
#  Server 2008 / 2008 R2            #
#####################################
missing = 0;
if (dotnet_46_installed)
{
  # Vista / 2008
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.deployment.dll", version:"4.6.118.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # 7 / 2008 R2
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.deployment.dll", version:"4.6.118.0", min_version:"4.6.0.0",  dir:"\Microsoft.NET\Framework\v4.0.30319");

 if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3098001");
  vuln += missing;
}

############# KB3098786 #############
#  .NET Framework 4.6/4.6 RC        #
#  Windows Vista, 7                 #
#  Server 2008 / 2008 R2            #
#####################################
missing = 0;
if (dotnet_46_installed)
{
  # Vista / 2008
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Web.dll", version:"4.6.118.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # 7 / 2008 R2
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Web.dll", version:"4.6.118.0", min_version:"4.6.0.0",  dir:"\Microsoft.NET\Framework\v4.0.30319");

 if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3098786");
  vuln += missing;
}

########## KB3098781 ################
#  .NET Framework 4.5, 4.5.1, 4.5.2 #
#  Windows Vista SP2,               #
#  Server 2008 SP2                  #
#  Windows 7 SP1,                   #
#  Server 2008 R2 SP1               #
#####################################
missing = 0;
if (dotnet_45_installed || dotnet_451_installed || dotnet_452_installed)
{
  # Vista SP2 / 2008 SP2
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Web.dll", version:"4.0.30319.18446", min_version:"4.0.30319.18400", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # 7 / 2008 R2 SP1
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Web.dll", version:"4.0.30319.18446", min_version:"4.0.30319.18400", dir:"\Microsoft.NET\Framework\v4.0.30319");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3098781");
vuln += missing;

########## KB3098778 ###########
#  .NET Framework 4.0          #
#  Windows Vista SP2,          #
#  Windows 7 SP1,              #
#  Windows Server 2008 SP2,    #
#  Windows Server 2008 R2 SP1  #
################################
missing = 0;
# Windows Vista SP2 / Server 2008 SP2
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Web.dll", version:"4.0.30319.34280", min_version:"4.0.30319.18000", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Web.dll", version:"4.0.30319.36330", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Windows 7 SP1 / 2008 R2 SP1
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Web.dll", version:"4.0.30319.34280", min_version:"4.0.30319.18000", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Web.dll", version:"4.0.30319.36330", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3098778");
vuln += missing;

########## KB3097988 #############
# .NET Framework 2.0 SP2         #
# Windows Vista SP2              #
# Windows Server 2008 SP2        #
##################################
missing = 0;
# GDR
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"dfdll.dll", version:"2.0.50727.4259", min_version:"2.0.50727.2000", dir:"\Microsoft.NET\Framework\v2.0.50727");
# LDR
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"dfdll.dll", version:"2.0.50727.8671", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3097988");
vuln += missing;

########### KB3097989 ############
# .NET Framework 3.5.1           #
# Windows 7 SP1                  #
# Windows Server 2008 R2 SP1     #
##################################
missing = 0;
# GDR
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"dfdll.dll", version:"2.0.50727.5493", min_version:"2.0.50727.2000", dir:"\Microsoft.NET\Framework\v2.0.50727");
# LDR
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"dfdll.dll", version:"2.0.50727.8671", min_version:"2.0.50727.6500", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3097989");
vuln += missing;


########## KB3097991 ###########
# .NET Framework 3.5           #
# Windows 8                    #
# Windows Server 2012          #
################################
missing = 0;
# GDR
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"dfdll.dll", version:"2.0.50727.6420", min_version:"2.0.50727.2000", dir:"\Microsoft.NET\Framework\v2.0.50727");
# LDR
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"dfdll.dll", version:"2.0.50727.8671", min_version:"2.0.50727.6500", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3097991");
vuln += missing;


########### KB3097992 #############
# .NET Framework 3.5              #
# Windows 8.1                     #
# Windows Server 2012 R2          #
###################################
missing = 0;
# LDR
missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"dfdll.dll", version:"2.0.50727.8671", min_version:"2.0.50727.8100",  dir:"\Microsoft.NET\Framework\v2.0.50727");
# GDR
missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"dfdll.dll", version:"2.0.50727.8017", min_version:"2.0.50727.4000",  dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3097992");
vuln += missing;

########### KB3097994 ############
# .NET Framework 4               #
# Windows Vista SP2              #
# Windows Server 2008 SP2        #
# Windows 7 SP1                  #
# Windows Server 2008 R2 SP1     #
##################################
missing = 0;
# Windows Vista/Server 2008 SP2
# GDR
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Deployment.dll", version:"4.0.30319.1039", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
# LDR
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Deployment.dll", version:"4.0.30319.2072", min_version:"4.0.30319.1500", dir:"\Microsoft.NET\Framework\v4.0.30319");

# Windows 7/Server 2008 R2 SP1
# GDR
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Deployment.dll", version:"4.0.30319.1039", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
# LDR
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Deployment.dll", version:"4.0.30319.2072", min_version:"4.0.30319.1500", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3097994");
vuln += missing;

########### KB3097997 ############
# .NET Framework 4.5.1/4.5.2     #
# Windows 8.1                    #
# Windows 8.1 RT                 #
# Windows Server 2012 R2         #
##################################
missing = 0;
if (dotnet_451_installed || dotnet_452_installed)
{
  # GDR
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.deployment.dll", version:"4.0.30319.34274", min_version:"4.0.30319.10000", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # LDR
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.deployment.dll", version:"4.0.30319.36323", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3097997");
vuln += missing;

########### KB3097996 ############
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
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Deployment.dll", version:"4.0.30319.34280", min_version:"4.0.30319.18000", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # LDR
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Deployment.dll", version:"4.0.30319.36330", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # Windows 7/Server 2008 R2 SP1
  # GDR
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Deployment.dll", version:"4.0.30319.34280", min_version:"4.0.30319.18000", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # LDR
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Deployment.dll", version:"4.0.30319.36330", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3097996");
vuln += missing;

############# KB3105213 #############
#  .NET Framework 3.5 and 4.6       #
#  Windows 10                       #
#####################################
missing = 0;
# .NET 4.6
missing += hotfix_is_vulnerable(os:"10", sp:0, os_build:"10240", file:"System.Deployment.dll", version:"4.6.114.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
# .NET 3.5
missing += hotfix_is_vulnerable(os:"10", sp:0, os_build:"10240", file:"System.Deployment.dll", version:"2.0.50727.8671", min_version:"2.0.50727.8100", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3105213");
vuln += missing;

# Report
if(vuln > 0)
{
  set_kb_item(name: 'www/0/XSS', value: TRUE);
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
