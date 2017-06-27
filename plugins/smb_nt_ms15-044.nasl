#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83440);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/19 18:02:19 $");

  script_cve_id("CVE-2015-1670", "CVE-2015-1671");
  script_bugtraq_id(74485, 74490);
  script_osvdb_id(121997, 121998);
  script_xref(name:"MSFT", value:"MS15-044");

  script_name(english:"MS15-044: Vulnerabilities in Microsoft Font Drivers Could Allow Remote Code Execution (3057110)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists due to
    improper handling of OpenType fonts by the Windows
    DirectWrite library. A remote attacker can exploit this
    vulnerability by convincing a user to open a file or
    visit a website containing a specially crafted OpenType
    font, resulting in the disclosure of sensitive
    information. (CVE-2015-1670)

  - A remote code execution vulnerability exists due to
    improper handling of TrueType font files by the Windows
    DirectWrite library. A remote attacker can exploit this
    vulnerability by convincing a user to open a specially
    crafted document or visit a website containing a
    specially crafted TrueType font file, resulting in
    execution of arbitrary code in the context of the
    current user. (CVE-2015-1671)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-044");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2003, Vista, 2008,
7, 2008 R2, 8, 2012, 8.1, and 2012 R2. Additionally, Microsoft has
released a set of patches for Office 2007, Office 2010, Live Meeting
2007 Console, Lync 2010, Lync 2010 Attendee, Lync 2013, Lync Basic
2013; and .NET Framework 3.0, 3.5, 3.5.1, 4, 4.5, 4.5.1, and 4.5.2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:live_meeting_console");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync_basic");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:silverlight");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "microsoft_owa_installed.nbin", "microsoft_lync_server_installed.nasl", "silverlight_detect.nasl", "ms_bulletin_checks_possible.nasl", "office_installed.nasl", "microsoft_net_framework_installed.nasl");
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

global_var bulletin, vuln, productname;

bulletin = 'MS15-044';
kbs = make_list(
  # .NET
  "3048068",
  "3048070",
  "3048071",
  "3048072",
  "3048073",
  "3048074",
  "3048077",
  # All Windows
  "3045171",
  "3065979", #3rd party check only
  # Office
  "2883029",
  "2881073",
  # Lync Client
  "3051467",
  "3051464",
  "3051465",
  "3051466",
  "3039779",
  # Silver Light
  "3056819"
);
vuln = 0;

###################################################################################
# Main
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
# Some of the 2k3 checks could flag XP 64, which is unsupported
if ("Windows XP" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

###################################################################################
# DOT NET CHECKS
function perform_dotnet_checks()
{
  local_var dotnet_452_installed, dotnet_451_installed, dotnet_45_installed;
  local_var ver, missing, count, installs, install;

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

  missing = 0;

  ########## KB 3048068 #############
  # .NET Framework 3.0 SP2         #
  # Windows Vista SP2              #
  # Windows Server 2008 SP2        #
  ##################################
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"wpfgfx_v0300.dll", version:"3.0.6920.4225", min_version:"3.0.6920.0", dir:"\Microsoft.NET\Framework\v3.0\WPF");
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"wpfgfx_v0300.dll", version:"3.0.6920.8671", min_version:"3.0.6920.7000", dir:"\Microsoft.NET\Framework\v3.0\WPF");

  if (missing > 0)
  {
    hotfix_add_report(bulletin:bulletin, kb:"3048068");
    vuln += missing;
    missing = 0;
  }

  ########### KB 3048070 ############
  # .NET Framework 3.5.1            #
  # Windows 7 SP1                   #
  # Windows Server 2008 R2 SP1      #
  ###################################
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"wpfgfx_v0300.dll", version:"3.0.6920.5466", min_version:"3.0.6920.0",  dir:"\Microsoft.NET\Framework\v3.0\WPF");
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"wpfgfx_v0300.dll", version:"3.0.6920.8671", min_version:"3.0.6920.7000",  dir:"\Microsoft.NET\Framework\v3.0\WPF");

  if (missing > 0)
  {
    hotfix_add_report(bulletin:bulletin, kb:"3048070");
    vuln += missing;
    missing = 0;
  }

  ########## KB 3048071 ###########
  # .NET Framework 3.5            #
  # Windows 8                     #
  # Windows Server 2012           #
  #################################
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"wpfgfx_v0300.dll", version:"3.0.6920.6418", min_version:"3.0.6920.0", dir:"\Microsoft.NET\Framework\v3.0\WPF");
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"wpfgfx_v0300.dll", version:"3.0.6920.8671", min_version:"3.0.6920.7000", dir:"\Microsoft.NET\Framework\v3.0\WPF");

  if (missing > 0)
  {
    hotfix_add_report(bulletin:bulletin, kb:"3048071");
    vuln += missing;
    missing = 0;
  }

  ########### KB 3048072 ############
  # .NET Framework 3.5              #
  # Windows 8.1                     #
  # Windows Server 2012 R2          #
  ###################################
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"wpfgfx_v0300.dll", version:"3.0.6920.8005", min_version:"3.0.6920.0", dir:"\Microsoft.NET\Framework\v3.0\WPF");
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"wpfgfx_v0300.dll", version:"3.0.6920.8671", min_version:"3.0.6920.8200", dir:"\Microsoft.NET\Framework\v3.0\WPF");

  if (missing > 0)
  {
    hotfix_add_report(bulletin:bulletin, kb:"3048072");
    vuln += missing;
    missing = 0;
  }

  ########## KB 3048073 #############
  # .NET Framework 3.0 SP2          #
  # Windows Server 2003 SP2         #
  ###################################
  missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"wpfgfx_v0300.dll", version:"3.0.6920.4082", min_version:"3.0.6920.0", dir:"\Microsoft.NET\Framework\v3.0\WPF");
  missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"wpfgfx_v0300.dll", version:"3.0.6920.8673", min_version:"3.0.6920.5000", dir:"\Microsoft.NET\Framework\v3.0\WPF");

  if (missing > 0)
  {
    hotfix_add_report(bulletin:bulletin, kb:"3048073");
    vuln += missing;
    missing = 0;
  }
  ########### KB 3048074 ############
  # .NET Framework 4                #
  # Windows Vista SP2               #
  # Windows Server 2008 SP2         # 
  # Windows Server 2003 SP2         #
  ###################################
  #LDR/GDR the same

  # Windows Server 2003 SP2
  missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"wpfgfx_v0400.dll", version:"4.0.30319.1034", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
  missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"wpfgfx_v0400.dll", version:"4.0.30319.2059", min_version:"4.0.30319.1200", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");

  # Windows Vista/Server 2008 SP2
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"wpfgfx_v0400.dll", version:"4.0.30319.1034", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"wpfgfx_v0400.dll", version:"4.0.30319.2059", min_version:"4.0.30319.1200", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");

  if (missing > 0)
  {
    hotfix_add_report(bulletin:bulletin, kb:"3048074");
    vuln += missing;
    missing = 0;
  }

  ########## KB 3048077 ############
  # .NET Framework 4.5/4.5.1/4.5.2 #
  # Windows Vista SP2              #
  # Windows Server 2008 SP2        #
  ##################################
  if (dotnet_45_installed || dotnet_451_installed || dotnet_452_installed)
  {
    missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"wpftxt_v0400.dll", version:"4.0.30319.34259", min_version:"4.0.30319.30000", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
    missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"wpftxt_v0400.dll", version:"4.0.30319.36297", min_version:"4.0.30319.34500", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
  }

  if (missing > 0)
  {
    hotfix_add_report(bulletin:bulletin, kb:"3048077");
    vuln += missing;
  }
}

###################################################################################
# KB3045171 Windows Checks
function perform_windows_checks()
{
  if (
    # Windows 8.1 / 2012 R2
    hotfix_is_vulnerable(os:"6.3", file:"win32k.sys", version:"6.3.9600.17796", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3045171") ||

    # Windows 7 / 2008 R2
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"win32k.sys", version:"6.1.7601.23038", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:"3045171") ||
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"win32k.sys", version:"6.1.7601.18834", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:"3045171") ||

    # Windows 8 / 2012
    hotfix_is_vulnerable(os:"6.2", file:"Win32k.sys", version:"6.2.9200.21457", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3045171") ||
    hotfix_is_vulnerable(os:"6.2", file:"Win32k.sys", version:"6.2.9200.17343", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3045171") ||

    # Vista / 2008
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32k.sys", version:"6.0.6002.23680", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3045171") ||
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32k.sys", version:"6.0.6002.19372", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3045171") ||

    # Windows 2003
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"win32k.sys", version:"5.2.3790.5615", dir:"\system32", bulletin:bulletin, kb:"3045171")
  ) vuln++;
}


###################################################################################
# KB2883029 / KB2881073 (Office Checks)
function perform_office_checks()
{
  local_var office_versions, office_sp;
  local_var path;

  office_versions = hotfix_check_office_version();
  if (office_versions["14.0"])
  {
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (!isnull(office_sp) && office_sp == 2)
    {
      path = hotfix_append_path(path:hotfix_get_officecommonfilesdir(officever:"14.0"), value:"\Microsoft Shared\Office14");
      if (hotfix_check_fversion(file:"Ogl.dll", version:"14.0.7148.5000", min_version:"14.0.0.0", path:path, bulletin:bulletin, kb:"2881073", product:"Microsoft Office 2010 SP2") == HCF_OLDER)
        vuln++;
    }
  }

  if (office_versions["12.0"])
  {
    office_sp = get_kb_item("SMB/Office/2007/SP");
    if (office_sp == 3)
    {
      path = hotfix_append_path(path:hotfix_get_officecommonfilesdir(officever:"12.0"), value:"\Microsoft Shared\Office12");
      if (hotfix_check_fversion(file:"Ogl.dll", version:"12.0.6719.5000", min_version:"12.0.0.0", path:path, bulletin:bulletin, kb:'2883029', product:"Microsoft Office 2007 SP3") == HCF_OLDER)
        vuln++;
    }
  }
}

###################################################################################
# Lync checks
function perform_lync_checks()
{
  local_var lync_count, lync_installs, lync_install;
  local_var count,install;

  lync_count = get_install_count(app_name:"Microsoft Lync");
  if (lync_count > 0)
  {
    lync_installs = get_installs(app_name:"Microsoft Lync");
    foreach lync_install (lync_installs[1])
    {
      if ("Live Meeting 2007 Console" >< lync_install["Product"])
      {
        if (hotfix_check_fversion(file:"pubutil.dll", version:"8.0.6362.229", min_version:"8.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"3051467", product:"Live Meeting 2007 Console") == HCF_OLDER)
          vuln++;
      }
      else if (lync_install["version"] =~ "^4\.0\." && "Server" >!< lync_install["Product"])
      {
        if ("attendee" >!< tolower(lync_install["Product"]))
        {
          if (hotfix_check_fversion(file:"communicator.exe", version:"4.0.7577.4461", min_version:"4.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"3051464", product:"Microsoft Lync 2010") == HCF_OLDER)
            vuln++;
        }
        else if ("attendee" >< tolower(lync_install["Product"]))
        {
          if ("user level" >< tolower(lync_install["Product"]))
          {
            if (hotfix_check_fversion(file:"MeetingJoinAxAOC.DLL", version:"4.0.7577.4461", min_version:"4.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"3051465", product:lync_install["Product"]) == HCF_OLDER)
              vuln++;
          }
          else
          {
            if (hotfix_check_fversion(file:"MeetingJoinAxAOC.DLL", version:"4.0.7577.4461", min_version:"4.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"3051466", product:lync_install["Product"]) == HCF_OLDER)
              vuln++;
          }
        }
      }
      else if (lync_install["version"] =~ "^15\.0\." && "Server" >!< lync_install["Product"])
      {
        if (hotfix_check_fversion(file:"Lync.exe", version:"15.0.4719.1000", min_version:"15.0.4569.1503", path:lync_install["path"], bulletin:bulletin, kb:"3039779", product:"Microsoft Lync 2013") == HCF_OLDER)
          vuln++;
      }
    }
  }
}

###################################################################################
# Silverlight Check
function perform_silverlight_checks()
{
  local_var slver, report, path;

  slver = get_kb_item("SMB/Silverlight/Version");
  if (slver && slver =~ "^5\." && ver_compare(ver:slver, fix:"5.1.40416.0",strict:FALSE) == -1)
  {
    path = get_kb_item("SMB/Silverlight/Path");
    if (isnull(path)) path = 'n/a';

    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + slver +
      '\n  Fixed version     : 5.1.40416.0' +
      '\n';
    hotfix_add_report(report, bulletin:bulletin, kb:"3056819");
    vuln++;
  }
}

perform_dotnet_checks();
perform_windows_checks();
perform_office_checks();
perform_lync_checks();
perform_silverlight_checks();

###################################################################################
# REPORT
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
