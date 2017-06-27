#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83356);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/06 17:11:39 $");

  script_cve_id("CVE-2015-1672", "CVE-2015-1673");
  script_bugtraq_id(74482, 74487);
  script_osvdb_id(122008, 122009);
  script_xref(name:"MSFT", value:"MS15-048");
  script_xref(name:"IAVA", value:"2015-A-0105");

  script_name(english:"MS15-048: Vulnerabilities in .NET Framework Could Allow Elevation of Privilege (3057134)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The version of the .NET Framework installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of the Microsoft .NET
Framework that is affected by multiple vulnerabilities :

  - A denial of service vulnerability exists in the
    Microsoft .NET Framework due to a recursion flaw that
    occurs when decrypting XML data. A remote attacker can
    exploit this, via specially crafted XML data, to degrade
    the performance of a .NET website. (CVE-2015-1672)

  - A privilege escalation vulnerability exists in the
    Microsoft .NET Framework due to improper handling of
    objects in memory by .NET's Windows Forms (WinForms)
    libraries. A remote attacker can exploit this, via a
    specially crafted partial trust application, to
    escalate privileges. (CVE-2015-1673)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-048");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for .NET Framework 1.1 SP1,
2.0 SP2, 3.5, 3.5.1, 4.0, 4.5, 4.5.1, and 4.5.2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/05/12");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/12");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:microsoft:windows");
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

bulletin = 'MS15-048';
kbs = make_list(
  '3023211',
  '3023213',
  '3023215',
  '3023217',
  '3023219',
  '3023220',
  '3023221',
  '3023222',
  '3023223',
  '3023224',
  '3032655',
  '3032662',
  '3032663',
  '3035485',
  '3035486',
  '3035487',
  '3035488',
  '3035489',
  '3035490' 
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

############ KB3035490 ##############
#  .NET Framework 4.5, 4.5.1, 4.5.2 #
#  Windows Vista SP2,               #
#  Server 2008 SP2,                 #
#  Windows 7 SP1,                   #
#  Windows 2008 R2 SP1              #
#####################################
missing = 0;
if(dotnet_45_installed || dotnet_451_installed || dotnet_452_installed)
{
  # Windows Vista SP2 / Server 2008 SP2
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Security.dll", version:"4.0.30319.34252", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Security.dll", version:"4.0.30319.36288", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # Windows 7 SP1 / 2008 R2 SP1
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Security.dll", version:"4.0.30319.34252", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Security.dll", version:"4.0.30319.36288", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
}
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3035490");
vuln += missing;

############ KB3035489 ##############
#  .NET Framework 4.5, 4.5.1, 4.5.2 #
#  Windows 8,                       #
#  Server 2012                      #
#####################################
missing = 0;
if(dotnet_45_installed || dotnet_451_installed || dotnet_452_installed)
{
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.Security.dll", version:"4.0.30319.34248", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.Security.dll", version:"4.0.30319.36283", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
}
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3035489");
vuln += missing;

######### KB3035488 ###########
#  .NET Framework 2.0 SP2     #
#  Server 2003 SP2            #
###############################
missing = 0;
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Security.dll", version:"2.0.50727.3665", min_version:"2.0.50727.2000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3035488");
vuln += missing;

########## KB3035487 ###########
#  .NET Framework 3.5          #
#  Windows 8.1,                #
#  Server 2012 R2              #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"System.Security.dll", version:"2.0.50727.8015", min_version:"2.0.50727.6000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"System.Security.dll", version:"2.0.50727.8652", min_version:"2.0.50727.8500", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3035487");
vuln += missing;

########## KB3035486 ###########
#  .NET Framework 3.5          #
#  Windows 8,                  #
#  Server 2012                 #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.Security.dll", version:"2.0.50727.6426", min_version:"2.0.50727.6000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.Security.dll", version:"2.0.50727.8652", min_version:"2.0.50727.7000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3035486");
vuln += missing;

########## KB3035485 ###########
#  .NET Framework 2.0 SP2      #
#  Windows Vista SP2,          #
#  Server 2008 SP2             #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Security.dll", version:"2.0.50727.8652", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Security.dll", version:"2.0.50727.4256", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3035485");
vuln += missing;

########## KB3032663 ###########
#  .NET Framework 4.5.1/4.5.2  #
#  Windows 8.1,                #
#  Server 2012 R2              #
################################
missing = 0;
if (dotnet_451_installed || dotnet_452_installed)
{
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"System.Security.dll", version:"4.0.30319.34248", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"System.Security.dll", version:"4.0.30319.36283", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3032663");
vuln += missing;

########## KB3032662 ###########
#  .NET Framework 4.0          #
#  Windows 2003 SP2,           #
#  Windows Vista SP2,          #
#  Windows 7 SP1,              #
#  Windows Server 2008 SP2,    #
#  Windows Server 2008 R2 SP1  #
################################
missing = 0;
# Server 2003 SP2
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Security.dll", version:"4.0.30319.1031", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Security.dll", version:"4.0.30319.2056", min_version:"4.0.30319.1200", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Windows Vista SP2 / Server 2008 SP2
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Security.dll", version:"4.0.30319.1031", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Security.dll", version:"4.0.30319.2056", min_version:"4.0.30319.1200", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Windows 7 SP1 / 2008 R2 SP1
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Security.dll", version:"4.0.30319.1031", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Security.dll", version:"4.0.30319.2056", min_version:"4.0.30319.1200", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3032662");
vuln += missing;

########## KB3032655 ###########
#  .NET Framework 3.5.1        #
#  Windows 7 SP1               #
#  Server 2008 R2 SP1          #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.security.dll", version: "2.0.50727.5490", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.security.dll", version: "2.0.50727.8652", min_version:"2.0.50727.5600", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3032655");
vuln += missing;

########### KB3023211 ##########
#  .NET Framework 1.1 SP1      #
#  Server 2003 SP2 32-bit      #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"5.2", arch:"x86", sp:2, file:"mscorlib.dll", version:"1.1.4322.2512", min_version:"1.1.4322.2000", dir:"\Microsoft.NET\Framework\v1.1.4322");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3023211");
vuln += missing;

########## KB3023215 ###########
#  .NET Framework 3.5.1        #
#  Windows 7 SP1,              #
#  Server 2008 R2 SP1          #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Windows.Forms.dll", version:"2.0.50727.8653", min_version:"2.0.50727.5600", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Windows.Forms.dll", version:"2.0.50727.5491", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3023215");
vuln += missing;

########## KB3023221 ###########
#  .NET Framework 4.0          #
#  Windows 2003 SP2,           #
#  Windows Vista SP2,          #
#  Windows 7,                  #
#  Windows Server 2008 SP2,    #
#  Windows Server 2008 R2      #
################################
missing = 0;
# Server 2003 SP2
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Windows.Forms.dll", version:"4.0.30319.1032", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Windows.Forms.dll", version:"4.0.30319.2057", min_version:"4.0.30319.1200", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Server 2008 SP2
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Windows.Forms.dll", version:"4.0.30319.1032", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Windows.Forms.dll", version:"4.0.30319.2057", min_version:"4.0.30319.1200", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Windows 7 / 2008 R2
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Windows.Forms.dll", version:"4.0.30319.1032", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Windows.Forms.dll", version:"4.0.30319.2057", min_version:"4.0.30319.1200", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3023221");
vuln += missing;

######### KB3023220 ###########
#  .NET Framework 2.0 SP2     #
#  Server 2003 SP2            #
###############################
missing = 0;
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Windows.Forms.dll", version:"2.0.50727.8655", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Windows.Forms.dll", version:"2.0.50727.3667", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3023220");
vuln += missing;

########## KB3023213 ###########
#  .NET Framework 2.0 SP2      #
#  Windows Vista SP2,          #
#  Server 2008 SP2             #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Windows.Forms.dll", version:"2.0.50727.8653", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Windows.Forms.dll", version:"2.0.50727.4257", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3023213");
vuln += missing;

############ KB3023223 ##############
#  .NET Framework 4.5, 4.5.1, 4.5.2 #
#  Windows 8,                       #
#  Server 2012                      #
#####################################
missing = 0;
if(dotnet_45_installed || dotnet_451_installed || dotnet_452_installed)
{
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.Windows.Forms.dll", version:"4.0.30319.34250", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.Windows.Forms.dll", version:"4.0.30319.36286", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
}
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3023223");
vuln += missing;

############ KB3023224 ##############
#  .NET Framework 4.5, 4.5.1, 4.5.2 #
#  Windows Vista SP2,               #
#  Server 2008 SP2,                 #
#  Windows 7 SP1,                   #
#  Windows 2008 R2 SP1              #
#####################################

missing = 0;
if(dotnet_45_installed || dotnet_451_installed || dotnet_452_installed)
{
  # Windows Vista SP2 / Server 2008 SP2
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Windows.Forms.dll", version:"4.0.30319.34251", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Windows.Forms.dll", version:"4.0.30319.36287", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # Windows 7 SP1 / 2008 R2 SP1
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Windows.Forms.dll", version:"4.0.30319.34251", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Windows.Forms.dll", version:"4.0.30319.36287", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
}
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3023224");
vuln += missing;

########## KB3023217 ###########
#  .NET Framework 3.5          #
#  Windows 8,                  #
#  Server 2012                 #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.Windows.Forms.dll", version:"2.0.50727.6427", min_version:"2.0.50727.6000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.Windows.Forms.dll", version:"2.0.50727.8653", min_version:"2.0.50727.7000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3023217");
vuln += missing;

########## KB3023219 ###########
#  .NET Framework 3.5          #
#  Windows 8.1,                #
#  Server 2012 R2              #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"System.Windows.Forms.dll", version:"2.0.50727.8015", min_version:"2.0.50727.6000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"System.Windows.Forms.dll", version:"2.0.50727.8653", min_version:"2.0.50727.8500", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3023219");
vuln += missing;

########## KB3023222 ###########
#  .NET Framework 4.5.1/4.5.2  #
#  Windows 8.1,                #
#  Server 2012 R2              #
################################
missing = 0;
if (dotnet_451_installed || dotnet_452_installed)
{
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"System.Windows.Forms.dll", version:"4.0.30319.34250", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"System.Windows.Forms.dll", version:"4.0.30319.36286", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3023222");
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
