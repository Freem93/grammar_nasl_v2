#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85348);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/06 17:11:39 $");

  script_cve_id(
    "CVE-2015-2432",
    "CVE-2015-2458",
    "CVE-2015-2459",
    "CVE-2015-2460",
    "CVE-2015-2461",
    "CVE-2015-2462",
    "CVE-2015-2435",
    "CVE-2015-2455",
    "CVE-2015-2456",
    "CVE-2015-2463",
    "CVE-2015-2464",
    "CVE-2015-2431",
    "CVE-2015-2433",
    "CVE-2015-2453",
    "CVE-2015-2454",
    "CVE-2015-2465"
  );
  script_bugtraq_id(
    76203,
    76207,
    76209,
    76210,
    76211,
    76213,
    76215,
    76216,
    76218,
    76223,
    76225,
    76235,
    76238,
    76239,
    76240,
    76241
  );
  script_osvdb_id(
    125679,
    125964,
    125965,
    125966,
    125967,
    125968,
    125969,
    125970,
    125971,
    125972,
    125973,
    125974,
    125975,
    125976,
    125977,
    125978,
    125979
  );
  script_xref(name:"MSFT", value:"MS15-080");
  script_xref(name:"IAVA", value:"2015-A-0196");

  script_name(english:"MS15-080 : Vulnerabilities in Microsoft Graphics Component Could Allow Remote Code Execution (3078662)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis",value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The remote Windows host is affected by multiple vulnerabilities :

  - Multiple remote code execution vulnerabilities exist due
    to the Windows Adobe Type Manager Library not properly
    handling specially crafted OpenType fonts. An attacker
    can exploit these, by using a crafted document or web
    page with embedded OpenType fonts, to execute arbitrary
    code in the context of the current user. (CVE-2015-2432,
    CVE-2015-2458, CVE-2015-2459, CVE-2015-2460,
    CVE-2015-2461, CVE-2015-2462)

  - Multiple remote code execution vulnerabilities exist in
    various components of Windows, .NET Framework, Office,
    Lync, and Silverlight due to a failure to properly handle
    TrueType fonts. An attacker can exploit these, by using
    a crafted document or web page with embedded TrueType
    fonts, to execute arbitrary code in the context of the
    current user. (CVE-2015-2435, CVE-2015-2455,
    CVE-2015-2456 CVE-2015-2463, CVE-2015-2464)

  - A remote code execution vulnerability exists due to
    Microsoft Office not properly handling Office Graphics
    Library (OGL) fonts. An attacker can exploit this, by
    using a crafted document or web page with embedded OGL
    fonts, to execute arbitrary code in the context of the
    user. (CVE-2015-2431)

  - A security feature bypass vulnerability exists due to
    a failure by the Windows kernel to properly initialize
    a memory address. An attacker, using a specially crafted
    application, can exploit this issue to bypass Kernel
    Address Space Layout Randomization (KASLR) and retrieve
    the base address of the kernel driver. (CVE-2015-2433)

  - An elevation of privilege vulnerability exists due to 
    a flaw in the Windows Client/Server Run-time Subsystem
    (CSRSS) when terminating a process when a user logs off.
    An attacker can exploit this vulnerability to run code
    that monitors the actions of users who log on to the
    system, allowing the disclosure of sensitive information
    which could be used to elevate privileges or execute
    code. (CVE-2015-2453)

  - A security feature bypass vulnerability exists due to
    the Windows kernel-mode driver not properly validating
    and enforcing impersonation levels. An attacker can
    exploit this to gain elevated privileges on a targeted
    system. (CVE-2015-2454)

  - A security feature bypass vulnerability exists due to
    the Windows shell not properly validating and enforcing
    impersonation levels. An attacker can exploit this to
    bypass impersonation-level security and gain elevated
    privileges on a targeted system. (CVE-2015-2465)");
  script_set_attribute(attribute:"see_also",value:"https://technet.microsoft.com/library/security/MS15-080");
  script_set_attribute(attribute:"solution",value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, RT, 2012, 8.1, RT 8.1, 2012 R2, and 10. Additionally, 
Microsoft has released a set of patches for Office 2007, Office 2010,
Microsoft Lync 2010, 2010 Attendee, 2013 SP1, Microsoft Live Meeting
2007; and .NET Framework 3.5, 3.5.1, 4, 4.5, 4.5.1, 4.5.2, and 4.6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS15-078 Microsoft Windows Font Driver Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/08/11");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/12");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:live_meeting_console");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync_basic");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:silverlight");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "microsoft_lync_server_installed.nasl", "silverlight_detect.nasl",  "microsoft_net_framework_installed.nasl", "office_installed.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

global_var bulletin, vuln, arch;

arch = get_kb_item_or_exit('SMB/ARCH');
vuln = 0;
bulletin = 'MS15-080';

kbs = make_list(
  '3054846',  # Office 2010 SP 2
  '3054890',  # Office 2007 SP 3
  '3055014',  # Microsoft Lync 2013 SP1
  '3072303',  # .NET Framework 3.0 SP2
  '3072305',  # .NET Framework 3.5.1
  '3072306',  # .NET Framework 3.5 (Windows 8)
  '3072307',  # .NET Framework 3.5 (Windows 8.1)
  '3072309',  # .NET Framework 4
  '3072310',  # .NET Framework 4.5/4.5.1/4.5.2
  '3072311',  # .NET Framework 4.6
  '3075590',  # Mictosoft Lync 2010 Attendee (admin level install) 
  '3075591',  # Microsoft Live Meeting 2007
  '3075592',  # Microsoft Lync 2010 Attendee (user level install)
  '3075593',  # Microsft Lync 2010
  '3078601',  # Windows (all but 10)
  '3080333',  # Microsoft Silverlight 5
  '3081436'   # Windows 10
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);
if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

# Windows Checks
function perform_windows_checks()
{
  if (
    # Windows 10
    hotfix_is_vulnerable(os:"10", sp:0, file:"ntdll.dll", version:"10.0.10240.16430", dir:"\system32", bulletin:bulletin, kb:'3081436') ||

    # Windows 8.1 / Windows Server 2012 R2
    hotfix_is_vulnerable(os:"6.3", sp:0, file:"atmfd.dll", version:"5.1.2.245", dir:"\system32", bulletin:bulletin, kb:'3078601') ||

    # Windows 8 / Windows Server 2012
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"atmfd.dll", version:"5.1.2.245", dir:"\system32", bulletin:bulletin, kb:'3078601') ||

    # Windows 7 and Windows Server 2008 R2
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"atmfd.dll", version:"5.1.2.245", dir:"\system32", bulletin:bulletin, kb:'3078601') ||

    # Vista / Windows 2008
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"atmfd.dll", version:"5.1.2.245", dir:"\system32", bulletin:bulletin, kb:'3078601') 
  )
    vuln++;
}

# dotnet checks
function perform_dotnet_checks()
{
  local_var dotnet_452_installed, dotnet_451_installed, dotnet_45_installed, dotnet_46_installed;
  local_var ver, missing, count, installs, install;

  # Determine if .NET 4.5, 4.5.1, or 4.5.2 is installed
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
      if (ver == "4.6") dotnet_46_installed = TRUE;
      if (ver == "4.5.1") dotnet_451_installed = TRUE;
      if (ver == "4.5.2") dotnet_452_installed = TRUE;
    }
  }

  ########## KB3072303 #############
  # .NET Framework 3.0 SP2         #
  # Windows Vista SP2              #
  # Windows Server 2008 SP2        #
  ##################################
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"wpfgfx_v0300.dll", version:"3.0.6920.4229", min_version:"3.0.6920.0", dir:"\Microsoft.NET\Framework\v3.0\WPF");
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"wpfgfx_v0300.dll", version:"3.0.6920.8684", min_version:"3.0.6920.7000", dir:"\Microsoft.NET\Framework\v3.0\WPF");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3072303");
  vuln += missing;

  ########### KB3072309 #############
  # .NET Framework 4                #
  # Windows Vista SP2               #
  # Windows Server 2008 SP2         # 
  ###################################
  missing = 0;
  # Windows Vista/Server 2008 SP2
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"wpfgfx_v0400.dll", version:"4.0.30319.1038", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"wpfgfx_v0400.dll", version:"4.0.30319.2065", min_version:"4.0.30319.1200", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3072309");
  vuln += missing;

  ########### KB3072310 ############
  # .NET Framework 4.5/4.5.1/4.5.2 #
  # Windows Vista SP2              #
  # Windows Server 2008 SP2        #
  ##################################
  missing = 0;
  if (dotnet_45_installed || dotnet_451_installed || dotnet_452_installed)
  {
    missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"wpftxt_v0400.dll", version:"4.0.30319.34273", min_version:"4.0.30319.30000", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
    missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"wpftxt_v0400.dll", version:"4.0.30319.36314", min_version:"4.0.30319.34500", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
  }

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3072310");
  vuln += missing;
 
  ############ KB3072311 ###########
  # .NET Framework 4.6             #
  # Windows Vista SP2              #
  # Windows Server 2008 SP2        #
  ##################################
  missing = 0;
  if (dotnet_46_installed)
  {
    missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"wpftxt_v0400.dll", version:"4.6.101.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
    if(arch == "x64")
      missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"wpftxt_v0400.dll", version:"4.6.101.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework64\v4.0.30319\WPF");
  }

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3072311");
  vuln += missing;

  ############ KB3072307 ############
  # .NET Framework 3.5              #
  # Windows 8.1                     #
  # Windows Server 2012 R2          #
  ###################################
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"wpfgfx_v0300.dll", version:"3.0.6920.8008", min_version:"3.0.6920.0", dir:"\Microsoft.NET\Framework\v3.0\WPF");
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"wpfgfx_v0300.dll", version:"3.0.6920.8684", min_version:"3.0.6920.8200", dir:"\Microsoft.NET\Framework\v3.0\WPF");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3072307");
  vuln += missing;

  ########### KB3072305 #############
  # .NET Framework 3.5.1            #
  # Windows 7 SP1                   #
  # Windows Server 2008 R2 SP1      #
  ###################################
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"wpfgfx_v0300.dll", version:"3.0.6920.5469", min_version:"3.0.6920.0",  dir:"\Microsoft.NET\Framework\v3.0\WPF");
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"wpfgfx_v0300.dll", version:"3.0.6920.8684", min_version:"3.0.6920.7000",  dir:"\Microsoft.NET\Framework\v3.0\WPF");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3072305");
  vuln += missing;

  ########### KB3072306 ###########
  # .NET Framework 3.5            #
  # Windows 8                     #
  # Windows Server 2012           #
  #################################
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"wpfgfx_v0300.dll", version:"3.0.6920.6421", min_version:"3.0.6920.0", dir:"\Microsoft.NET\Framework\v3.0\WPF");
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"wpfgfx_v0300.dll", version:"3.0.6920.8684", min_version:"3.0.6920.7000", dir:"\Microsoft.NET\Framework\v3.0\WPF");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3072306");
  vuln += missing;

  ############ KB3072307 ############
  # .NET Framework 3.5              #
  # Windows 8.1                     #
  # Windows Server 2012 R2          #
  ###################################
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"wpfgfx_v0300.dll", version:"3.0.6920.8008", min_version:"3.0.6920.0", dir:"\Microsoft.NET\Framework\v3.0\WPF");
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"wpfgfx_v0300.dll", version:"3.0.6920.8684", min_version:"3.0.6920.8200", dir:"\Microsoft.NET\Framework\v3.0\WPF");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3072307");
  vuln += missing;
}

# KB3054890 / KB3054846 (Office Checks)
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
      if (hotfix_check_fversion(file:"Ogl.dll", version:"14.0.7155.5000", min_version:"14.0.0.0", path:path, bulletin:bulletin, kb:"3054846", product:"Microsoft Office 2010 SP2") == HCF_OLDER)
        vuln++;
    }
  }

  if (office_versions["12.0"])
  {
    office_sp = get_kb_item("SMB/Office/2007/SP");
    if (office_sp == 3)
    {
      path = hotfix_append_path(path:hotfix_get_officecommonfilesdir(officever:"12.0"), value:"\Microsoft Shared\Office12");
      if (hotfix_check_fversion(file:"Ogl.dll", version:"12.0.6725.5000", min_version:"12.0.0.0", path:path, bulletin:bulletin, kb:'3054890', product:"Microsoft Office 2007 SP2") == HCF_OLDER)
        vuln++;
    }
  }
}

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
        if (hotfix_check_fversion(file:"pubutil.dll", version:"8.0.6362.236", min_version:"8.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"3075591", product:"Live Meeting 2007 Console") == HCF_OLDER)
          vuln++;
      }
      else if (lync_install["version"] =~ "^4\.0\." && "Server" >!< lync_install["Product"])
      {
        if ("Attendee" >!< lync_install["Product"])
        {
          if (hotfix_check_fversion(file:"communicator.exe", version:"4.0.7577.4476", min_version:"4.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"3075593", product:"Microsoft Lync 2010") == HCF_OLDER)
            vuln++;
        }
        else if ("Attendee" >< lync_install["Product"])
        {
          if ("user level" >< tolower(lync_install["Product"]))
          {
            if (hotfix_check_fversion(file:"MeetingJoinAxAOC.DLL", version:"4.0.7577.4476", min_version:"4.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"3075592", product:lync_install["Product"]) == HCF_OLDER)
              vuln++;
          }
          else
          {
            if (hotfix_check_fversion(file:"MeetingJoinAxAOC.DLL", version:"4.0.7577.4476", min_version:"4.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"3075590", product:lync_install["Product"]) == HCF_OLDER)
              vuln++;
          }
        }
      }
      else if (lync_install["version"] =~ "^15\.0\." && "Server" >!< lync_install["Product"])
      {
        if (hotfix_check_fversion(file:"Lync.exe", version:"15.0.4745.1000", min_version:"15.0.4569.1503", path:lync_install["path"], bulletin:bulletin, kb:"3055014", product:"Microsoft Lync 2013") == HCF_OLDER)
          vuln++;
      }
    }
  }
}

# Silverlight Check
function perform_silverlight_checks()
{
  local_var slver, report, path;

  slver = get_kb_item("SMB/Silverlight/Version");
  if (slver && slver =~ "^5\." && ver_compare(ver:slver, fix:"5.1.40728.0",strict:FALSE) == -1)
  {
    path = get_kb_item("SMB/Silverlight/Path");
    if (isnull(path)) path = 'n/a';

    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + slver +
      '\n  Fixed version     : 5.1.40728.0' +
      '\n';
    hotfix_add_report(report,bulletin:bulletin, kb:"3080333");
    vuln += 1;
  }
}

perform_windows_checks();
perform_dotnet_checks();
perform_office_checks();
perform_silverlight_checks();
perform_lync_checks();

if(vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
