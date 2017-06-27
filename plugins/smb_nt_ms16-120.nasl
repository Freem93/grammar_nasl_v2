#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94017);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/24 14:05:10 $");

  script_cve_id(
    "CVE-2016-3209",
    "CVE-2016-3262",
    "CVE-2016-3263",
    "CVE-2016-3270",
    "CVE-2016-3393",
    "CVE-2016-3396",
    "CVE-2016-7182"
  );
  script_bugtraq_id(
    93377,
    93380,
    93385,
    93390,
    93394,
    93395,
    93403
  );
  script_osvdb_id(
    145510,
    145511,
    145512,
    145513,
    145514,
    145515,
    145516
  );
  script_xref(name:"MSFT", value:"MS16-120");
  script_xref(name:"IAVA", value:"2016-A-0278");

  script_name(english:"MS16-120: Security Update for Microsoft Graphics Component (3192884)");
  script_summary(english:"Checks the version of win32k.sys.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple vulnerabilities :

  - Multiple information disclosure vulnerabilities exist in
    the Windows GDI component due to improper handling of
    objects in memory. A local attacker can exploit these
    vulnerabilities, via a specially crafted application, to
    predict memory offsets in a call stack and bypass the
    Address Space Layout Randomization (ASLR) feature,
    resulting in the disclosure of memory contents.
    (CVE-2016-3209, CVE-2016-3262, CVE-2016-3263)

  - An elevation of privilege vulnerability exists in the
    Windows kernel due to improper handling of objects in
    memory. A local attacker can exploit this to elevate
    privileges and execute code in kernel mode.
    (CVE-2016-3270)

  - A remote code execution vulnerability exists in the
    Windows GDI component due to improper handling of
    objects in memory. An unauthenticated, remote attacker
    can exploit this vulnerability by convincing a user to
    visit a specially crafted website or open a specially
    crafted file, resulting in the execution of arbitrary
    code in the context of the current user. (CVE-2016-3393)

  - A remote code execution vulnerability exists in the
    Windows font library due to improper handling of
    embedded fonts. An unauthenticated, remote attacker
    can exploit this vulnerability by convincing a user to
    visit a specially crafted website or open a specially
    crafted document file, resulting in the execution of
    arbitrary code in the context of the current user.
    (CVE-2016-3396)
  
  - An elevation of privilege vulnerability exists in the
    Windows GDI component due to improper handling of
    objects in memory. A local attacker can exploit this to
    elevate privileges and execute code in kernel mode.
    (CVE-2016-7182)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-120");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, and 10. Additionally, Microsoft
has released a set of patches for Office 2007, Office 2010, Word
Viewer, Skype for Business 2016, Lync 2010, Lync 2013, Live Meeting
2007 Console, .NET Framework 3.0 SP2, .NET Framework 3.5, .NET
Framework 3.5.1, .NET Framework 4.5.2, .NET Framework 4.6, and
Silverlight 5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:skype_for_business");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync_basic");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync_attendee");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:live_meeting_console");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:silverlight");

  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "office_installed.nasl", "microsoft_lync_server_installed.nasl", "microsoft_net_framework_installed.nasl", "silverlight_detect.nasl", "smb_check_rollup.nasl");
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

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS16-120';
kbs = make_list(
  "3191203", # Windows Vista / 2008
  "3192391", # Windows 7 / 2008 R2 Security Only
  "3185330", # Windows 7 / 2008 R2 Monthly Rollup
  "3192392", # Windows 8.1 / 2012 R2 Security Only
  "3185331", # Windows 8.1 / 2012 R2 / RT 8.1 Monthly Rollup
  "3192393", # Windows 2012 Security Only
  "3185332", # Windows 2012 Monthly Rollup
  "3192440", # Windows 10 RTM
  "3192441", # Windows 10 1511
  "3194798", # Windows 10 1607
  "3188726", # .NET 3.0 SP2 Security Only
  "3189039", # .NET 4.5.2 Security Only
  "3189040", # .NET 4.6 Security Only
  "3188730", # .NET 3.5.1 Security Only
  "3188732", # .NET 3.5 on Windows 8.1 / 2012 R2 Security Only
  "3188731", # .NET 3.5 on Windows 2012 Security Only
  "3188735", # .NET 3.0 SP2 Monthly Rollup
  "3189051", # .NET 4.5.2 Monthly Rollup
  "3189052", # .NET 4.6 Monthly Rollup
  "3188740", # .NET 3.5.1 Monthly Rollup
  "3188743", # .NET 3.5 on Windows 8.1 / 2012 R2 Monthly Rollup
  "3188741", # .NET 3.5 on Windwos 2012 Monthly Rollup
  "3118301", # Office 2007 SP3
  "3118317", # Office 2010 SP2
  "3118394", # Office Word Viewer
  "3118327", # Skype for Biz 2016
  "3118348", # Lync 2013 SP1
  "3188397", # Lync 2010
  "3188399", # Lync 2010 Attendee (User level)
  "3188400", # Lync 2010 Attendee (Admin level)
  "3189647", # Live Meeting 2007 Console
  "3193713"  # Silverlight 5
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname)
  audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = 0;

#  "3191203", # Windows Vista / 2008
#  "3192391", # Windows 7 / 2008 R2 Security Only
#  "3185330", # Windows 7 / 2008 R2 Monthly Rollup
#  "3192392", # Windows 8.1 / 2012 R2 Security Only
#  "3185331", # Windows 8.1 / 2012 R2 / RT 8.1 Monthly Rollup
#  "3192393", # Windows 2012 Security Only
#  "3185332", # Windows 2012 Monthly Rollup
#  "3192440", # Windows 10 RTM
#  "3192441", # Windows 10 1511
#  "3194798", # Windows 10 1607
function windows_os_is_vuln()
{
  if (
    #  "3194798", # Windows 10 1607
    smb_check_rollup(os:"10", sp:0, os_build:"14393", rollup_date:"10_2016", bulletin:bulletin, rollup_kb_list:make_list(3194798)) ||

    #  "3192441", # Windows 10 1511
    smb_check_rollup(os:"10", sp:0, os_build:"10586", rollup_date:"10_2016", bulletin:bulletin, rollup_kb_list:make_list(3192441)) ||

    #  "3192440", # Windows 10 RTM
    smb_check_rollup(os:"10", sp:0, os_build:"10240", rollup_date:"10_2016", bulletin:bulletin, rollup_kb_list:make_list(3192440)) ||

    #  "3192392", # Windows 8.1 / 2012 R2 Security Only
    #  "3185331", # Windows 8.1 / 2012 R2 / RT 8.1 Monthly Rollup
    smb_check_rollup(os:"6.3", sp:0, rollup_date:"10_2016", bulletin:bulletin, rollup_kb_list:make_list(3192392, 3185331)) ||

    #  "3192393", # Windows 2012 Security Only
    #  "3185332", # Windows 2012 Monthly Rollup
    smb_check_rollup(os:"6.2", sp:0, rollup_date:"10_2016", bulletin:bulletin, rollup_kb_list:make_list(3192393, 3185332)) ||

    #  "3192391", # Windows 7 / 2008 R2 Security Only
    #  "3185330", # Windows 7 / 2008 R2 Monthly Rollup
    smb_check_rollup(os:"6.1", sp:1, rollup_date:"10_2016", bulletin:bulletin, rollup_kb_list:make_list(3192391, 3185330)) ||

    #  "3191203", # Windows Vista / 2008
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32k.sys", version:"6.0.6002.19693", min_version:"6.0.6002.16000", dir:"\system32", bulletin:bulletin, kb:"3191203") ||
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32k.sys", version:"6.0.6002.24017", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3191203")
  ) vuln += 1;
}


# "3118301", # Office 2007 SP3
# "3118317", # Office 2010 SP2
# "3118394", # Office Word Viewer
function office_is_vuln()
{
  local_var office_versions, office_sp;
  local_var path;

  office_versions = hotfix_check_office_version();

  # 2010 SP2
  if (office_versions["14.0"])
  {
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (!isnull(office_sp) && office_sp == 2)
    {
      path = hotfix_append_path(path:hotfix_get_officecommonfilesdir(officever:"14.0"), value:"\Microsoft Shared\Office14");
      if (hotfix_check_fversion(file:"Ogl.dll", version:"14.0.7174.5000", min_version:"14.0.0.0", path:path, bulletin:bulletin, kb:"3118317", product:"Microsoft Office 2010 SP2") == HCF_OLDER)
        vuln++;
    }
  }

  # 2007 SP3
  if (office_versions["12.0"])
  {
    office_sp = get_kb_item("SMB/Office/2007/SP");
    if (office_sp == 3)
    {
      path = hotfix_append_path(path:hotfix_get_officecommonfilesdir(officever:"12.0"), value:"\Microsoft Shared\Office12");
      if (hotfix_check_fversion(file:"Ogl.dll", version:"12.0.6757.5000", min_version:"12.0.0.0", path:path, bulletin:bulletin, kb:'3118301', product:"Microsoft Office 2007 SP3") == HCF_OLDER)
         vuln++;
    }
  }

  # Word Viewer
  if (!empty_or_null(get_kb_list("SMB/Office/WordViewer/*/ProductPath")))
  {
    path = hotfix_append_path(path:hotfix_get_officecommonfilesdir(officever:"11.0"), value:"Microsoft Shared\Office11");
    if (hotfix_check_fversion(file:"gdiplus.dll", version:"11.0.8435.0", min_version:"11.0.0.0", path:path, bulletin:bulletin, kb:'3118394', product:"Microsoft Word Viewer") == HCF_OLDER)
      vuln++;
  }
}

# "3118327", # Skype for Biz 2016
# "3118348", # Lync 2013 SP1
# "3188397", # Lync 2010
# "3188399", # Lync 2010 Attendee (User level)
# "3188400", # Lync 2010 Attendee (Admin level)
# "3189647", # Live Meeting 2007 Console
function lync_is_vuln()
{
  local_var lync_count, lync_installs, lync_install;

  lync_count = get_install_count(app_name:"Microsoft Lync");

  # Nothing to do
  if (int(lync_count) <= 0)
    return FALSE;

  lync_installs = get_installs(app_name:"Microsoft Lync");
  foreach lync_install (lync_installs[1])
  {
    if ("Live Meeting 2007 Console" >< lync_install["Product"])
    {
     if (hotfix_check_fversion(file:"pubutil.dll", version:"8.0.6362.262", min_version:"8.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"3189647", product:"Live Meeting 2007 Console") == HCF_OLDER)
       vuln++;
    }
    if (lync_install["version"] =~ "^4\.0\." && "Server" >!< lync_install["Product"])
    {
      # Lync 2010
      if ("Attendee" >!< lync_install["Product"])
      {
        if (hotfix_check_fversion(file:"communicator.exe", version:"4.0.7577.4521", min_version:"4.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"3188397", product:"Microsoft Lync 2010") == HCF_OLDER)
          vuln++;
      }
      # Lync 2010 Attendee
      else if ("Attendee" >< lync_install["Product"])
      {
        if ("user level" >< tolower(lync_install["Product"])) # User
        {
          if (hotfix_check_fversion(file:"MeetingJoinAxAOC.DLL", version:"4.0.7577.4521", min_version:"4.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"3188399", product:lync_install["Product"]) == HCF_OLDER)
            vuln++;
        }
        else # Admin
        {
          if (hotfix_check_fversion(file:"MeetingJoinAxAOC.DLL", version:"4.0.7577.4521", min_version:"4.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"3188400", product:lync_install["Product"]) == HCF_OLDER)
            vuln++;
        }
      }
    }
    # Lync 2013
    else if (lync_install["version"] =~ "^15\.0\." && "Server" >!< lync_install["Product"])
    {
      if (hotfix_check_fversion(file:"Lync.exe", version:"15.0.4867.1000", min_version:"15.0.4700.1000", path:lync_install["path"], bulletin:bulletin, kb:"3118348", product:"Microsoft Lync 2013 (Skype for Business)") == HCF_OLDER)
        vuln++;
    }
    # Skype for Business 2016
    else if (lync_install["version"] =~ "^16\.0\." && "Server" >!< lync_install["Product"])
    {
      # Office 365 Deferred channel
      if (lync_install['Channel'] == "Deferred")
        if (hotfix_check_fversion(file:"Lync.exe", version:"16.0.6965.2092", channel:"Deferred", channel_product:"Lync", path:lync_install["path"], bulletin:bulletin, kb:"3118327", product:"Skype for Business 2016") == HCF_OLDER)
          vuln++;

      # Office 365 First Release for Deferred channel
      if (lync_install['Channel'] == "First Release for Deferred")
        if (hotfix_check_fversion(file:"Lync.exe", version:"16.0.6741.2081", channel:"First Release for Deferred", channel_product:"Lync", path:lync_install["path"], bulletin:bulletin, kb:"3118327", product:"Skype for Business 2016") == HCF_OLDER)
          vuln++;

      # Office 365 Current channel
      if (lync_install['Channel'] == "Current")
        if (hotfix_check_fversion(file:"Lync.exe", version:"16.0.7369.2038", channel:"Current", channel_product:"Lync", path:lync_install["path"], bulletin:bulletin, kb:"3118327", product:"Skype for Business 2016") == HCF_OLDER)
          vuln++;

      # KB
      if (lync_install['Channel'] == "MSI" || empty_or_null(lync_install['Channel']))
        if (hotfix_check_fversion(file:"Lync.exe", version:"16.0.4444.1000", channel:"MSI", channel_product:"Lync", path:lync_install["path"], bulletin:bulletin, kb:"3118327", product:"Skype for Business 2016") == HCF_OLDER)
          vuln++;
    }
  }
}


# "3188726", # .NET 3.0 SP2 Security Only
# "3189039", # .NET 4.5.2 Security Only
# "3189040", # .NET 4.6 Security Only
# "3188730", # .NET 3.5.1 Security Only
# "3188732", # .NET 3.5 on Windows 8.1 / 2012 R2 Security Only
# "3188731", # .NET 3.5 on Windows 2012 Security Only
# "3188735", # .NET 3.0 SP2 Monthly Rollup
# "3189051", # .NET 4.5.2 Monthly Rollup
# "3189052", # .NET 4.6 Monthly Rollup
# "3188740", # .NET 3.5.1 Monthly Rollup
# "3188743", # .NET 3.5 on Windows 8.1 / 2012 R2 Monthly Rollup
# "3188741", # .NET 3.5 on Windwos 2012 Monthly Rollup
function dotnet_is_vuln()
{
  local_var dotnet_452_installed, dotnet_46_installed, dotnet_461_installed, dotnet_35_installed;
  local_var ver, missing, count, installs, install;


  # Determine if .NET 4.5.2 or 4.6 is installed
  dotnet_452_installed = FALSE;
  dotnet_46_installed  = FALSE;
  dotnet_35_installed  = FALSE;

  count = get_install_count(app_name:'Microsoft .NET Framework');
  if (count > 0)
  {
    installs = get_installs(app_name:'Microsoft .NET Framework');
    foreach install(installs[1])
    {
      ver = install["version"];
      if (ver == "4.6") dotnet_46_installed = TRUE;
      if (ver == "4.5.2") dotnet_452_installed = TRUE;
      if (ver == "3.5") dotnet_35_installed = TRUE;
    }
  }

  # "3188726", # .NET 3.0 SP2 Security Only
  # "3188735", # .NET 3.0 SP2 Monthly Rollup
  # Only on Vista / 2008
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"wpfgfx_v0300.dll", version:"3.0.6920.8720", min_version:"3.0.6920.0", dir:"\Microsoft.NET\Framework\v3.0\WPF");
  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3188726");
  vuln += missing;

  if (dotnet_35_installed)
  {
    # "3188730", # .NET 3.5.1 Security Only
    # "3188740", # .NET 3.5.1 Monthly Rollup
    # Only on 7 / 2008 R2
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"wpfgfx_v0300.dll", version:"3.0.6920.8720", dir:"\Microsoft.NET\Framework\v3.0\WPF");
    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3188730");
    vuln += missing;

    # "3188731", # .NET 3.5 on Windows 2012 Security Only
    # "3188741", # .NET 3.5 on Windwos 2012 Monthly Rollup
    # Only on 2012
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"wpfgfx_v0300.dll", version:"3.0.6920.8720", dir:"\Microsoft.NET\Framework\v3.0\WPF");
    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3188731");
    vuln += missing;

    # "3188732", # .NET 3.5 on Windows 8.1 / 2012 R2 Security Only
    # "3188743", # .NET 3.5 on Windows 8.1 / 2012 R2 Monthly Rollup
    # Only on 8.1 / 2012 R2
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"wpfgfx_v0300.dll", version:"3.0.6920.8720", dir:"\Microsoft.NET\Framework\v3.0\WPF");
    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3188732");
    vuln += missing;
  }


  if (dotnet_452_installed)
  {
    # "3189039", # .NET 4.5.2 Security Only
    # "3189051", # .NET 4.5.2 Monthly Rollup
    # Only on Vista / 2008
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"wpfgfx_v0400.dll", version:"4.0.30319.36367", dir:"\Microsoft.NET\Framework\v4.0.30319");
    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3189039");
    vuln += missing;
  }

  if (dotnet_46_installed)
  {
    # "3189040", # .NET 4.6 Security Only
    # "3189052", # .NET 4.6 Monthly Rollup
    # Only on Vista / 2008
    missing = 0;
    missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"wpfgfx_v0400.dll", version:"4.6.1085.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
    if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3189040");
    vuln += missing;
  }

}

# "3193713"  # Silverlight 5
function silverlight_is_vuln()
{
  local_var silver, path, report, fix;
  silver = get_kb_item("SMB/Silverlight/Version");
  if (!isnull(silver) && silver =~ "^5\.")
  {
    fix = "5.1.50901.0";
    if (ver_compare(ver:silver, fix:fix) == -1)
    {
      path = get_kb_item("SMB/Silverlight/Path");
      if (isnull(path)) path = 'n/a';

      report =
        '\n  Path              : ' + path +
        '\n  Installed version : ' + silver +
        '\n  Fixed version     : ' + fix +
        '\n';
      hotfix_add_report(report, bulletin:bulletin, kb:"3193713");
      vuln++;
    }
  }
}

dotnet_is_vuln();
office_is_vuln();
lync_is_vuln();
silverlight_is_vuln();
windows_os_is_vuln();

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
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}
