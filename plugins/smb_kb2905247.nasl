#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71323);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/03 21:58:18 $");

  script_name(english:"MS KB2905247: Insecure ASP.NET Site Configuration Could Allow Elevation of Privilege");
  script_summary(english:"Checks the version of .NET .dll files.");

  script_set_attribute(attribute:"synopsis", value:
"The .NET Framework installed on the remote Windows host is affected by
a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the .NET Framework installed on the remote Windows host
is affected by a privilege escalation vulnerability that allows a
remote attacker to inject and execute arbitrary code in the context of
the service account for the ASP.NET server.

This advisory was re-released on September 9, 2014 to offer the
security update via Microsoft Update, and to address an issue that
occasionally caused 'Page.IsPostBack' to return an incorrect value in
some of the affected software.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/2905247");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for .NET Framework 1.1, 2.0,
3.5, 3.5.1, 4.0, 4.5, and 4.5.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("wmi_enum_iis_components.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "microsoft_net_framework_installed.nasl");
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

if (hotfix_check_iis_installed() <= 0) audit(AUDIT_NOT_INST, "IIS");

iis_comps = get_kb_list("WMI/IIS/Component/*/Description");
if(isnull(iis_comps))
  exit(0, "No IIS ISAPI extensions found on the remote IIS server.");

asp_net_1_flag = FALSE;
asp_net_2_flag = FALSE;
asp_net_4_flag = FALSE;

foreach key (keys(iis_comps))
{
  comp = iis_comps[key];
  i = key - 'WMI/IIS/Component/' - '/Description';
  enabled = get_kb_item("WMI/IIS/Component/" + i + "/Allowed");
  if(!enabled) continue;

  if("ASP.NET" >< comp)
  {
    if("4.0.30319" >< comp)
      asp_net_4_flag = TRUE;
    else if("2.0.50727" >< comp)
      asp_net_2_flag = TRUE;
    else if("1.1.4322" >< comp)
      asp_net_1_flag = TRUE;
  }
}

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

get_kb_item_or_exit("SMB/Registry/Enumerated");
win_ver = get_kb_item_or_exit('SMB/WindowsVersion');

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# RT 8.1 is not affected
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if (win_ver == '6.3' && "Windows Embedded" >< productname) exit(0, "The host is running "+productname+" and is, therefore, not affected.");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

dotnet_451_installed = FALSE;
dotnet_45_installed  = FALSE;

# Determine if .NET 4.5 or 4.5.1 is installed
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

if(asp_net_4_flag)
{
  ######## KB2895210 #########
  #  .NET Framework 4.5.1 RC #
  #  Windows 7               #
  #  Server 2008 R2          #
  #  Vista                   #
  #  Server 2008             #
  ############################
  if (dotnet_451_installed)
  {
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.web.dll", version: "4.0.30319.18340", min_version:"4.0.30319.18300", dir:"\Microsoft.NET\Framework\v4.0.30319");
    missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.web.dll", version: "4.0.30319.19340", min_version:"4.0.30319.19300", dir:"\Microsoft.NET\Framework\v4.0.30319");
    missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.web.dll", version: "4.0.30319.18340", min_version:"4.0.30319.18300", dir:"\Microsoft.NET\Framework\v4.0.30319");
    missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.web.dll", version: "4.0.30319.19340", min_version:"4.0.30319.19300", dir:"\Microsoft.NET\Framework\v4.0.30319");

    vuln += missing;
  }

  ######## KB2894855 ############
  #  .NET Framework 4.5 / 4.5.1 #
  #  Windows 8                  #
  #  Server 2012                #
  ###############################
  if (dotnet_45_installed || dotnet_451_installed)
  {
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.web.dll", version: "4.0.30319.34212", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
    missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.web.dll", version: "4.0.30319.36215", min_version:"4.0.30319.36000", dir:"\Microsoft.NET\Framework\v4.0.30319");

    vuln += missing;
  }

  ######## KB2901550 #########
  #  .NET Framework 4.5.1    #
  #  Server 2012 R2 Preview  #
  #  Windows 8.1 Preview     #
  ############################
  if (dotnet_451_installed)
  {
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.web.dll", version: "4.0.30319.33011", min_version:"4.0.30319.33000", dir:"\Microsoft.NET\Framework\v4.0.30319");

    vuln += missing;
  }

  ######## KB2894856 #########
  #  .NET Framework 4.5.1    #
  #  Windows 8.1             #
  #  Server 2012 R2          #
  ############################
  if (dotnet_451_installed)
  {
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.web.dll", version: "4.0.30319.34212", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
    missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.web.dll", version: "4.0.30319.36215", min_version:"4.0.30319.36000", dir:"\Microsoft.NET\Framework\v4.0.30319");

    vuln += missing;
  }

  ######## KB2894854 ###############
  #  .NET Framework 4.5 / 4.5.1    #
  #  Windows 7                     #
  #  Server 2008 R2                #
  #  Vista                         #
  #  Server 2008                   #
  ##################################
  if (dotnet_45_installed || dotnet_451_installed)
  {
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.web.dll", version: "4.0.30319.34237", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
    missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.web.dll", version: "4.0.30319.36249", min_version:"4.0.30319.36000", dir:"\Microsoft.NET\Framework\v4.0.30319");
    missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.web.dll", version: "4.0.30319.34237", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
    missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.web.dll", version: "4.0.30319.36249", min_version:"4.0.30319.36000", dir:"\Microsoft.NET\Framework\v4.0.30319");

    vuln += missing;
  }

  ######## KB2894850 #########
  #  .NET Framework 4.5      #
  #  Windows 8               #
  #  Windows 2012            #
  ############################
  if (dotnet_45_installed)
  {
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.web.dll", version: "4.0.30319.18062", min_version:"4.0.30319.18000", dir:"\Microsoft.NET\Framework\v4.0.30319");
    missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.web.dll", version: "4.0.30319.19127", min_version:"4.0.30319.19000", dir:"\Microsoft.NET\Framework\v4.0.30319");

    vuln += missing;
  }

  ######## KB2894849 #########
  #  .NET Framework 4.5.1    #
  #  Windows 7               #
  #  Server 2008 R2          #
  #  Vista                   #
  #  Server 2008             #
  ############################
  if (dotnet_45_installed)
  {
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.web.dll", version: "4.0.30319.18061", min_version:"4.0.30319.18000", dir:"\Microsoft.NET\Framework\v4.0.30319");
    missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.web.dll", version: "4.0.30319.19126", min_version:"4.0.30319.19000", dir:"\Microsoft.NET\Framework\v4.0.30319");
    missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.web.dll", version: "4.0.30319.18061", min_version:"4.0.30319.18000", dir:"\Microsoft.NET\Framework\v4.0.30319");
    missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.web.dll", version: "4.0.30319.19126", min_version:"4.0.30319.19000", dir:"\Microsoft.NET\Framework\v4.0.30319");

    vuln += missing;
  }

  ########## KB2894842 ###########
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
  missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.Web.dll", version:"4.0.30319.1025", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.Web.dll", version:"4.0.30319.2042", min_version:"4.0.30319.2000", dir:"\Microsoft.NET\Framework\v4.0.30319");

  # Windows XP SP2 x64 / Server 2003 SP2
  missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Web.dll", version:"4.0.30319.1025", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Web.dll", version:"4.0.30319.2042", min_version:"4.0.30319.2000", dir:"\Microsoft.NET\Framework\v4.0.30319");

  # Windows Vista SP2 / Server 2008 SP2
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Web.dll", version:"4.0.30319.1025", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Web.dll", version:"4.0.30319.2042", min_version:"4.0.30319.2000", dir:"\Microsoft.NET\Framework\v4.0.30319");

  # Windows 7 / 2008 R2
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Web.dll", version:"4.0.30319.1025", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Web.dll", version:"4.0.30319.2042", min_version:"4.0.30319.2000", dir:"\Microsoft.NET\Framework\v4.0.30319");

  vuln += missing;
}

if(asp_net_2_flag)
{
  ########## KB2894844 ###########
  #  .NET Framework 3.5.1        #
  #  Windows 7 SP1               #
  #  Server 2008 R2 SP1          #
  ################################
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.web.dll", version: "2.0.50727.5477", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.web.dll", version: "2.0.50727.7041", min_version:"2.0.50727.5600", dir:"\Microsoft.NET\Framework\v2.0.50727");

  vuln += missing;

  ######## KB2895209 #########
  #  .NET Framework 3.5      #
  #  Server 2012 R2 Preview  #
  #  Windows 8.1 Preview     #
  ############################
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.web.dll", version: "2.0.50727.7821", min_version:"2.0.50727.7000", dir:"\Microsoft.NET\Framework\v2.0.50727");

  vuln += missing;

  ######## KB2894852 #########
  #  .NET Framework 3.5      #
  #  Server 2012 R2          #
  #  Windows 8.1             #
  ############################
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.web.dll", version: "2.0.50727.8010", min_version:"2.0.50727.7900", dir:"\Microsoft.NET\Framework\v2.0.50727");
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"system.web.dll", version: "2.0.50727.8631", min_version:"2.0.50727.8600", dir:"\Microsoft.NET\Framework\v2.0.50727");

  vuln += missing;

  ######## KB2894851 #########
  #  .NET Framework 3.5      #
  #  Server 2012             #
  #  Windows 8               #
  ############################
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.web.dll", version: "2.0.50727.6412", min_version:"2.0.50727.6000", dir:"\Microsoft.NET\Framework\v2.0.50727");
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.web.dll", version: "2.0.50727.7041", min_version:"2.0.50727.7000", dir:"\Microsoft.NET\Framework\v2.0.50727");

  vuln += missing;

  ########## KB894847 ###########
  #  .NET Framework 2.0 SP2      #
  #  Windows Vista SP2,          #
  #  Server 2008 SP2             #
  ################################
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.web.dll", version:"2.0.50727.4247", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"system.web.dll", version:"2.0.50727.7041", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");

  vuln += missing;

  ########## KB2894843 ###########
  #  .NET Framework 2.0 SP2      #
  #  Windows XP SP3,             #
  #  Windows 2003 SP2            #
  ################################
  missing = 0;
  # Windows XP SP3
  missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.web.dll", version:"2.0.50727.3657", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");
  missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.web.dll", version:"2.0.50727.7043", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
  # Server 2003 SP2
  missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.web.dll", version:"2.0.50727.3657", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");
  missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.web.dll", version:"2.0.50727.7043", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");

  vuln += missing;
}

if(asp_net_1_flag)
{
  ########## KB2894845 ###########
  #  .NET Framework 1.1 SP 1     #
  #  Windows Server 2003 32-bit  #
  ################################
  missing = 0;
  missing += hotfix_is_vulnerable(os:"5.2", arch:"x86", sp:2, file:"System.Web.dll", version:"1.1.4322.2504", dir:"\Microsoft.NET\Framework\v1.1.4322");

  vuln += missing;
}

# Reporting
if (vuln > 0)
{
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
