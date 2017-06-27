#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73985);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2014-1806");
  script_bugtraq_id(67286);
  script_osvdb_id(106903);
  script_xref(name:"EDB-ID", value:"35280");
  script_xref(name:"MSFT", value:"MS14-026");

  script_name(english:"MS14-026: Vulnerability in .NET Framework Could Allow Elevation of Privilege (2958732)");
  script_summary(english:"Checks version of system.runtime.remoting.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The version of the .NET Framework installed on the remote host is
affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of the Microsoft .NET Framework
that is affected by a privilege escalation vulnerability due to the
way that .NET Framework handles TypeFilterLevel checks for some
malformed objects.

Note that this vulnerability only affects applications that use .NET
Remoting.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS14-026");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for .NET Framework 1.1 SP1,
2.0 SP2, 3.5, 3.5.1, 4.0, 4.5, and 4.5.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/14");

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

# Windows Embedded is not supported by Nessus
# There are cases where this plugin is flagging embedded
# hosts improperly since this update does not apply
# to those machines
productname = get_kb_item("SMB/ProductName");
if ("Windows Embedded" >< productname)
  exit(0, "Nessus does not support bulletin / patch checks for Windows Embedded.");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS14-026';
kbs = make_list(
  "2931352",
  "2931354",
  "2931356",
  "2931357",
  "2931358",
  "2931365",
  "2931366",
  "2931367",
  "2931368",
  "2932079"
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# Windows 2008 Server Server Core is not affected.
if ('6.0' >< get_kb_item("SMB/WindowsVersion") && hotfix_check_server_core()) audit(AUDIT_WIN_SERVER_CORE);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
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

########## KB2931352 ###########
# .NET Framework 1.1 SP 1      #
# Windows Server 2003 SP2      #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"5.2", arch:"x86", sp:2, file:"mscorlib.dll", version:"1.1.4322.2506", min_version:"1.1.4322.2000", dir:"\Microsoft.NET\Framework\v1.1.4322");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2931352");
vuln += missing;

########## KB2931354 ###########
# .NET Framework 2.0 SP2       #
# Windows Vista SP2            #
# Windows Server 2008 SP2      #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Web.dll", version:"2.0.50727.7057", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Web.dll", version:"2.0.50727.4252", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2931354");
vuln += missing;

########## KB2931356 ###########
# .NET Framework 3.5.1         #
# Windows 7 SP1                #
# Windows Server 2008 R2 SP1   #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Web.dll", version:"2.0.50727.5483", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Web.dll", version:"2.0.50727.7057", min_version:"2.0.50727.7000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2931356");
vuln += missing;

########## KB2931357 ###########
# .NET Framework 3.5           #
# Windows 8                    #
# Windows Server 2012          #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.runtime.remoting.dll", version:"2.0.50727.6416", min_version:"2.0.50727.0", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.runtime.remoting.dll", version:"2.0.50727.7055", min_version:"2.0.50727.7000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2931357");
vuln += missing;

########## KB2931358 ###########
# .NET Framework 3.5           #
# Windows 8.1                  #
# Windows Server 2012 R2       #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.runtime.remoting.dll", version:"2.0.50727.8606", min_version:"2.0.50727.8600", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.runtime.remoting.dll", version:"2.0.50727.8003", min_version:"2.0.50727.0", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2931358");
vuln += missing;

########## KB2931365 ###########
# .NET Framework 4             #
# Windows Server 2003 SP2      #
# Windows Vista SP2            #
# Windows Server 2008 SP2      #
# Windows 7 for SP1            #
# Windows Server 2008 R2 SP1   #
################################
missing = 0;
# Windows Server 2003 SP2
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Runtime.Remoting.dll", version:"4.0.30319.1023", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Runtime.Remoting.dll", version:"4.0.30319.2036", min_version:"4.0.30319.2000", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Windows Vista/Server 2008 SP2
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Runtime.Remoting.dll", version:"4.0.30319.1023", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Runtime.Remoting.dll", version:"4.0.30319.2036", min_version:"4.0.30319.2000", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Windows 7/Server 2008 R2 SP1
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Runtime.Remoting.dll", version:"4.0.30319.1023", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Runtime.Remoting.dll", version:"4.0.30319.2036", min_version:"4.0.30319.2000", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2931365");
vuln += missing;

########## KB2931366 ###########
# .NET Framework 4.5.1         #
# Windows 8.1                  #
# Windows Server 2012 R2       #
################################
missing = 0;
if (dotnet_451_installed)
{
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.runtime.remoting.dll", version:"4.0.30319.34107", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.runtime.remoting.dll", version:"4.0.30319.36115", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2931366");
vuln += missing;

########## KB2931367 ###########
# .NET Framework 4.5/4.5.1     #
# Windows 8                    #
# Windows Server 2012          #
################################
missing = 0;
if (dotnet_45_installed || dotnet_451_installed)
{
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.runtime.remoting.dll", version:"4.0.30319.34107", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.runtime.remoting.dll", version:"4.0.30319.36105", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2931367");
vuln += missing;

########## KB2931368 ###########
# .NET Framework 4.5/4.5.1     #
# Windows Vista SP2            #
# Windows Server 2008 SP2      #
# Windows 7 SP1                #
# Windows Server 2008 R2 SP1   #
################################
missing = 0;
if (dotnet_45_installed || dotnet_451_installed)
{
  # Windows Vista/Server 2008 SP2
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Runtime.Remoting.dll", version:"4.0.30319.34108", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Runtime.Remoting.dll", version:"4.0.30319.36106", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
  # Windows 7/Server 2008 R2 SP1
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Runtime.Remoting.dll", version:"4.0.30319.34108", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Runtime.Remoting.dll", version:"4.0.30319.36106", min_version:"4.0.30319.35000", dir:"\Microsoft.NET\Framework\v4.0.30319");
}

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2931368");
vuln += missing;

########## KB2932079 ###########
# .NET Framework 2.0 SP2       #
# Windows Server 2003 SP2      #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Runtime.Remoting.dll", version:"2.0.50727.3659", min_version:"2.0.50727.0", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Runtime.Remoting.dll", version:"2.0.50727.7055", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2932079");
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
