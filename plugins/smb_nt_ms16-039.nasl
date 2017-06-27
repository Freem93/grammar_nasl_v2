#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90433);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/07/18 20:50:59 $");

  script_cve_id(
    "CVE-2016-0143",
    "CVE-2016-0145",
    "CVE-2016-0165",
    "CVE-2016-0167"
  );
  script_bugtraq_id(
    85896,
    85899,
    85900,
    85903
  );
  script_osvdb_id(
    136962,
    136963,
    136964,
    136965
  );
  script_xref(name:"MSFT", value:"MS16-039");
  script_xref(name:"IAVA", value:"2016-A-0091");

  script_name(english:"MS16-039: Security Update for Microsoft Graphics Component (3148522)");
  script_summary(english:"Checks the version of win32k.sys.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple vulnerabilities :
  
  - Multiple elevation of privilege vulnerabilities exist in
    the Windows kernel-mode driver due to a failure to
    properly handle objects in memory. An attacker can
    exploit these vulnerabilities to execute arbitrary code
    in kernel mode. (CVE-2016-0143, CVE-2016-0165,
    CVE-2016-0167)

  - A remote code execution vulnerability exists in the
    Windows font library due to improper handling of
    embedded fonts. An attacker can exploit this
    vulnerability by convincing a user to open a file or
    visit a website containing specially crafted embedded
    fonts, resulting in the execution of arbitrary code in
    the context of the current user. (CVE-2016-0145)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-039");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, and 10. Additionally, Microsoft
has released a set of patches for Office 2007, Office 2010,
Word Viewer, Skype for Business 2016, Lync 2010, Lync 2013, Live
Meeting 2007 Console, .NET framework 3.0 SP2, .NET framework 3.5, and
.NET framework 3.5.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/12");

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
  
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "office_installed.nasl", "microsoft_lync_server_installed.nasl", "microsoft_net_framework_installed.nasl");
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

bulletin = 'MS16-039';
kbs = make_list(
  "3145739", # Not Windows 10
  "3147461", # Windows 10 1511
  "3147458", # Windows 10 TRM
  "3114542", # Office 2007 SP3
  "3114566", # Office 2010 SP2
  "3114985", # Office Word Viewer
  "3142041", # .NET 3.0 SP2 Visa / 2008
  "3142042", # .NET 3.5.1 7 / 2008 R2 
  "3142045", # .NET 3.5 8.1 / 2012 R2
  "3142043", # .NET 3.5 2012
  "3114960", # Skype for Biz 2016
  "3114944", # Lync 2013
  "3144427", # Lync 2010
  "3144428", # 2010 Attendee (User level)
  "3144429", # 2010 Attendee (Admin level)
  "3144432"  # Live meeting 2007 Console
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

#KB 3147458, 3147461, 3145739
function windows_os_is_vuln()
{
  if (
    # 10 threshold 2 (aka 1511)
    hotfix_is_vulnerable(os:"10", sp:0, file:"win32kfull.sys", version:"10.0.10586.212", min_version:"10.0.10586.0", dir:"\system32", bulletin:bulletin, kb:"3147458") ||

    # 10 RTM
    hotfix_is_vulnerable(os:"10", sp:0, file:"win32kfull.sys", version:"10.0.10240.16771", dir:"\system32", bulletin:bulletin, kb:"3147461") ||

    # Windows 8.1 / Windows Server 2012 R2
    hotfix_is_vulnerable(os:"6.3", sp:0, file:"win32k.sys", version:"6.3.9600.18290", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3145739") ||

    # Windows 8 / Windows Server 2012
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"win32k.sys", version:"6.2.9200.21824", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3145739") ||

    # Windows 7 / Server 2008 R2
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"win32k.sys", version:"6.1.7601.23407", min_version:"6.1.7601.16000", dir:"\system32", bulletin:bulletin, kb:"3145739") ||

    # Vista / Windows Server 2008
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32k.sys", version:"6.0.6002.19626", min_version:"6.0.6002.16000", dir:"\system32", bulletin:bulletin, kb:"3145739") ||
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32k.sys", version:"6.0.6002.23943", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3145739")
  ) vuln += 1;
}

#KB 3114985 , 3114542, 3114566
#Make sure to add dependency for office_installed.nasl
function office_is_vuln()
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
      if (hotfix_check_fversion(file:"Ogl.dll", version:"14.0.7168.5000", min_version:"14.0.0.0", path:path, bulletin:bulletin, kb:"3114566", product:"Microsoft Office 2010 SP2") == HCF_OLDER)
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
      if (hotfix_check_fversion(file:"Ogl.dll", version:"12.0.6746.5000", min_version:"12.0.0.0", path:path, bulletin:bulletin, kb:'3114542', product:"Microsoft Office 2007 SP3") == HCF_OLDER)
         vuln++;
    }
  }

  # Word Viewer
  if (!empty_or_null(get_kb_list("SMB/Office/WordViewer/*/ProductPath")))
  {
    path = hotfix_append_path(path:hotfix_get_officecommonfilesdir(officever:"11.0"), value:"Microsoft Shared\Office11");
    if (hotfix_check_fversion(file:"gdiplus.dll", version:"11.0.8426.0", min_version:"11.0.0.0", path:path, bulletin:bulletin, kb:'3114985', product:"Microsoft Word Viewer") == HCF_OLDER)
      vuln++;
  }
}

#KB 3114960, 3114944, 3144427, 3144428, 3144429, 3144432 Lync checks
#Make sure to add dependency for microsoft_lync_server_installed.nasl
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
     if (hotfix_check_fversion(file:"pubutil.dll", version:"8.0.6362.252", min_version:"8.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"3144432", product:"Live Meeting 2007 Console") == HCF_OLDER)
       vuln++;
    }
    if (lync_install["version"] =~ "^4\.0\." && "Server" >!< lync_install["Product"])
    {
      # Lync 2010
      if ("Attendee" >!< lync_install["Product"])
      {
        if (hotfix_check_fversion(file:"communicator.exe", version:"4.0.7577.4500", min_version:"4.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"3144427", product:"Microsoft Lync 2010") == HCF_OLDER)
          vuln++;
      }
      # Lync 2010 Attendee
      else if ("Attendee" >< lync_install["Product"])
      {
        if ("user level" >< tolower(lync_install["Product"])) # User
        {
          if (hotfix_check_fversion(file:"MeetingJoinAxAOC.DLL", version:"4.0.7577.4498", min_version:"4.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"3144428", product:lync_install["Product"]) == HCF_OLDER)
            vuln++;
        }
        else # Admin
        {
          if (hotfix_check_fversion(file:"MeetingJoinAxAOC.DLL", version:"4.0.7577.4498", min_version:"4.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"3144429", product:lync_install["Product"]) == HCF_OLDER)
            vuln++;
        }
      }
    }
    # Lync 2013
    else if (lync_install["version"] =~ "^15\.0\." && "Server" >!< lync_install["Product"])
    {
      if (hotfix_check_fversion(file:"Lync.exe", version:"15.0.4809.1000", min_version:"15.0.4569.1503", path:lync_install["path"], bulletin:bulletin, kb:"3114944", product:"Microsoft Lync 2013 (Skype for Business)") == HCF_OLDER)
        vuln++;
    }
    # Skype for Business 2016
    else if (lync_install["version"] =~ "^16\.0\." && "Server" >!< lync_install["Product"])
    {
      # Office 365 Deferred channel
      if (hotfix_check_fversion(file:"Lync.exe", version:"16.0.6001.1073", channel:"Deferred", channel_product:"Lync", path:lync_install["path"], bulletin:bulletin, kb:"3114960", product:"Skype for Business 2016") == HCF_OLDER)
        vuln++;
      # Office 365 First Release for Deferred channel
      if (hotfix_check_fversion(file:"Lync.exe", version:"16.0.6741.2026", channel:"First Release for Deferred", channel_product:"Lync", path:lync_install["path"], bulletin:bulletin, kb:"3114960", product:"Skype for Business 2016") == HCF_OLDER)
        vuln++;
      # Office 365 Current channel
      if (hotfix_check_fversion(file:"Lync.exe", version:"16.0.6769.2017", channel:"Current", channel_product:"Lync", path:lync_install["path"], bulletin:bulletin, kb:"3114960", product:"Skype for Business 2016") == HCF_OLDER)
        vuln++;
      # KB
      if (hotfix_check_fversion(file:"Lync.exe", version:"16.0.4363.1000", channel:"MSI", channel_product:"Lync", path:lync_install["path"], bulletin:bulletin, kb:"3114960", product:"Skype for Business 2016") == HCF_OLDER)
        vuln++;
    }
  }
}

#KB 3142041, 3142042, 3142043, 3142045
# Make sure to add dependency for microsoft_net_framework_installed.nasl
function dotnet_is_vuln()
{
  local_var dotnet_452_installed, dotnet_46_installed, dotnet_461_installed, dotnet_35_installed;
  local_var ver, missing, count, installs, install;

  # Determine if .NET 4.5.2 or 4.6 is installed
  dotnet_452_installed = FALSE;
  dotnet_46_installed  = FALSE;
  dotnet_461_installed = FALSE;
  dotnet_35_installed  = FALSE;

  count = get_install_count(app_name:'Microsoft .NET Framework');
  if (count > 0)
  {
    installs = get_installs(app_name:'Microsoft .NET Framework');
    foreach install(installs[1])
    {
      ver = install["version"];
      if (ver == "4.6.1") dotnet_461_installed = TRUE;
      if (ver == "4.6") dotnet_46_installed = TRUE;
      if (ver == "4.5.2") dotnet_452_installed = TRUE;
      if (ver == "3.5") dotnet_35_installed = TRUE;
    }
  }


  ############ KB3142041 ############
  # .NET Framework 3.0              #
  # Windows Vista                   #
  # Windows 2008                    #
  ###################################
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"wpfgfx_v0300.dll", version:"3.0.6920.4235", min_version:"3.0.6920.0", dir:"\Microsoft.NET\Framework\v3.0\WPF");
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"wpfgfx_v0300.dll", version:"3.0.6920.8712", min_version:"3.0.6920.7000", dir:"\Microsoft.NET\Framework\v3.0\WPF");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3142041");
  vuln += missing;


  ########### KB3142042 #############
  # .NET Framework 3.5.1            #
  # Windows 7 SP1                   #
  # Windows Server 2008 R2 SP1      #
  ###################################
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"wpfgfx_v0300.dll", version:"3.0.6920.8712", min_version:"3.0.6920.0",    dir:"\Microsoft.NET\Framework\v3.0\WPF");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3142042");
  vuln += missing;


  ########### KB3142045 ###########
  # .NET Framework 3.5            #
  # Windows 8.1                   #
  # Windows Server 2012 R2        #
  #################################
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"wpfgfx_v0300.dll", version:"3.0.6920.8712", min_version:"3.0.6920.0",    dir:"\Microsoft.NET\Framework\v3.0\WPF");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3142045");
  vuln += missing;


  ############ KB3142043 ############
  # .NET Framework 3.5              #
  # Windows Server 2012             #
  ###################################
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"wpfgfx_v0300.dll", version:"3.0.6920.8712", min_version:"3.0.6920.0",    dir:"\Microsoft.NET\Framework\v3.0\WPF");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3142043");
  vuln += missing;

  ############# KB3147458 #############
  #  .NET Framework 3.5               #
  #  Windows 10                       #
  #####################################
  missing = 0;
  # .NET 3.5
  missing += hotfix_is_vulnerable(os:"10", sp:0, file:"wpfgfx_v0300.dll", version:"3.0.6920.8712", min_version:"3.0.6920.0", dir:"\Microsoft.NET\Framework\v3.0\WPF");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3147458");
  vuln += missing;
}

dotnet_is_vuln();
office_is_vuln();
lync_is_vuln();
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
  audit(AUDIT_HOST_NOT, 'affected');
}

