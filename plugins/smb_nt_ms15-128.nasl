#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87257);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/03/08 15:07:20 $");

  script_cve_id("CVE-2015-6106", "CVE-2015-6107", "CVE-2015-6108");
  script_bugtraq_id(78497, 78498, 78499);
  script_osvdb_id(131328, 131329, 131330);
  script_xref(name:"MSFT", value:"MS15-128");
  script_xref(name:"IAVA", value:"2015-A-0308");

  script_name(english:"MS15-128: Security Update for Microsoft Graphics Component to Address Remote Code Execution (3104503)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple remote code execution
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by multiple remote code execution
vulnerabilities due to improper handling of embedded fonts by the
Windows font library. A remote attacker can exploit these by
convincing a user to open a file or visit a website containing a
specially crafted embedded font, resulting in execution of arbitrary
code in the context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/ms15-128.aspx");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, RT, 2012, 8.1, RT 8.1, 2012 R2, and 10. Additionally,
Microsoft has released a set of patches for Office 2007, Office 2010,
Word Viewer, Lync 2010, Lync 2010 Attendee, Lync 2013, Lync Basic
2013, Skype for Business 2016, Live Meeting 2007 Console, Silverlight;
and .NET framework 3.0 SP2, 3.5, 3.5.1, 4, 4.5.1, 4.5.2, and 4.6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2007");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2010");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:live_meeting:2007");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync:2010");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync:2010:attendee");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync:2013");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync_basic:2013");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:skype_for_business:2016");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:silverlight");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "office_installed.nasl", "microsoft_lync_server_installed.nasl", "silverlight_detect.nasl");
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
bulletin = 'MS15-128';

kbs = make_list(
  "3085612",
  "3085616",
  "3099860",
  "3099862",
  "3099863",
  "3099864",
  "3099866",
  "3099869",
  "3099874",
  "3106614",
  "3109094",
  "3114351",
  "3114372",
  "3114478",
  "3115871",
  "3115872",
  "3115873",
  "3115875",
  "3116869",
  "3116900"
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
winver = get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);
if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

# Windows Checks
function perform_windows_checks()
{
  if (
    hotfix_is_vulnerable(os:"10", sp:0, file:"gdiplus.dll", version:"10.0.10586.20", min_version:"10.0.10586.0", dir:"\system32", bulletin:bulletin, kb:'3116900') ||
    hotfix_is_vulnerable(os:"10", sp:0, file:"gdiplus.dll", version:"10.0.10240.16603", dir:"\system32", bulletin:bulletin, kb:'3116869') ||
    # 8.1 / 2012 R2
    hotfix_is_vulnerable(os:"6.3", sp:0, file:"dwrite.dll", version:"6.3.9600.18123", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3109094") ||
    # 8 / 2012
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"dwrite.dll", version:"6.2.9200.17568", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3109094") ||
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"dwrite.dll", version:"6.2.9200.21687", min_version:"6.2.9200.20000 ", dir:"\system32", bulletin:bulletin, kb:"3109094") ||
    # 7 / 2008 R2
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"dwrite.dll", version:"6.2.9200.17568", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3109094") ||
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"dwrite.dll", version:"6.2.9200.21687", min_version:"6.2.9200.20000 ", dir:"\system32", bulletin:bulletin, kb:"3109094") ||
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"dwrite.dll", version:"6.1.7601.19061", min_version:"6.1.7601.16000", dir:"\system32", bulletin:bulletin, kb:"3109094") ||
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"dwrite.dll", version:"6.1.7601.23265", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:"3109094") ||
    # Vista / 2008
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"dwrite.dll", version:"7.0.6002.19535", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3109094") ||
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"dwrite.dll", version:"7.0.6002.23845", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:"3109094")
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

  ########## KB3099860 #############
  # .NET Framework 3.0 SP2         #
  # Windows Vista SP2              #
  # Windows Server 2008 SP2        #
  ##################################
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"wpfgfx_v0300.dll", version:"3.0.6920.4230", min_version:"3.0.6920.0", dir:"\Microsoft.NET\Framework\v3.0\WPF");
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"wpfgfx_v0300.dll", version:"3.0.6920.8693", min_version:"3.0.6920.7000", dir:"\Microsoft.NET\Framework\v3.0\WPF");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3099860");
  vuln += missing;

  ########### KB3099866 #############
  # .NET Framework 4                #
  # Windows Vista SP2               #
  # Windows Server 2008 SP2         # 
  ###################################
  missing = 0;
  # Windows Vista/Server 2008 SP2
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"wpfgfx_v0400.dll", version:"4.0.30319.1044", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
  missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"wpfgfx_v0400.dll", version:"4.0.30319.2077", min_version:"4.0.30319.1200", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2099866");
  vuln += missing;

  ########### KB3099869 ############
  # .NET Framework 4.5/4.5.1/4.5.2 #
  # Windows Vista SP2              #
  # Windows Server 2008 SP2        #
  ##################################
  missing = 0;
  if (dotnet_45_installed || dotnet_451_installed || dotnet_452_installed)
  {
    missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"wpftxt_v0400.dll", version:"4.0.30319.34280", min_version:"4.0.30319.30000", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
    missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"wpftxt_v0400.dll", version:"4.0.30319.36330", min_version:"4.0.30319.34500", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
  }

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3099869");
  vuln += missing;
 
  ############ KB3099874 ###########
  # .NET Framework 4.6             #
  # Windows Vista SP2              #
  # Windows Server 2008 SP2        #
  ##################################
  missing = 0;
  if (dotnet_46_installed)
  {
    missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"wpftxt_v0400.dll", version:"4.6.118.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework\v4.0.30319\WPF");
    if(arch == "x64")
      missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"wpftxt_v0400.dll", version:"4.6.118.0", min_version:"4.6.0.0", dir:"\Microsoft.NET\Framework64\v4.0.30319\WPF");
  }

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3099874");
  vuln += missing;

  ############ KB3099864 ############
  # .NET Framework 3.5              #
  # Windows 8.1                     #
  # Windows Server 2012 R2          #
  ###################################
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"wpfgfx_v0300.dll", version:"3.0.6920.8009", min_version:"3.0.6920.0", dir:"\Microsoft.NET\Framework\v3.0\WPF");
  missing += hotfix_is_vulnerable(os:"6.3", sp:0, file:"wpfgfx_v0300.dll", version:"3.0.6920.8693", min_version:"3.0.6920.8200", dir:"\Microsoft.NET\Framework\v3.0\WPF");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3099864");
  vuln += missing;

  ########### KB3099862 #############
  # .NET Framework 3.5.1            #
  # Windows 7 SP1                   #
  # Windows Server 2008 R2 SP1      #
  ###################################
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"wpfgfx_v0300.dll", version:"3.0.6920.5470", min_version:"3.0.6920.0",  dir:"\Microsoft.NET\Framework\v3.0\WPF");
  missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"wpfgfx_v0300.dll", version:"3.0.6920.8693", min_version:"3.0.6920.7000",  dir:"\Microsoft.NET\Framework\v3.0\WPF");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3099862");
  vuln += missing;

  ########### KB3099863 ###########
  # .NET Framework 3.5            #
  # Windows 8                     #
  # Windows Server 2012           #
  #################################
  missing = 0;
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"wpfgfx_v0300.dll", version:"3.0.6920.6422", min_version:"3.0.6920.0", dir:"\Microsoft.NET\Framework\v3.0\WPF");
  missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"wpfgfx_v0300.dll", version:"3.0.6920.8693", min_version:"3.0.6920.7000", dir:"\Microsoft.NET\Framework\v3.0\WPF");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3099863");
  vuln += missing;

  ############# KB3116869 #############
  #  .NET Framework 3.5               #
  #  Windows 10                       #
  #####################################
  missing = 0;
  # .NET 3.5
  missing += hotfix_is_vulnerable(os:"10", sp:0, file:"wpfgfx_v0300.dll", version:"3.0.6920.8693", min_version:"3.0.6920.0", dir:"\Microsoft.NET\Framework\v3.0\WPF");

  if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"3116869");
  vuln += missing;
}

# KB 3085546 / KB 3085529 (Office Checks)
function perform_office_checks()
{
  local_var office_versions, office_sp;
  local_var path, wvinst, wvkb;

  office_versions = hotfix_check_office_version();
  # Office 2010 is only affected on Windows versions earlier than Vista
  if (winver !~ '^([0-5\\.]|6\\.0$)')
  {
    if (office_versions["14.0"])
    {
      office_sp = get_kb_item("SMB/Office/2010/SP");
      if (!isnull(office_sp) && office_sp == 2)
      {
        path = hotfix_append_path(path:hotfix_get_officecommonfilesdir(officever:"14.0"), value:"\Microsoft Shared\Office14");
        if (hotfix_check_fversion(file:"Ogl.dll", version:"14.0.7164.5000", min_version:"14.0.0.0", path:path, bulletin:bulletin, kb:"3085612", product:"Microsoft Office 2010 SP2") == HCF_OLDER)
          vuln++;
      }
    }
  }

  if (office_versions["12.0"])
  {
    office_sp = get_kb_item("SMB/Office/2007/SP");
    if (office_sp == 3)
    {
      path = hotfix_append_path(path:hotfix_get_officecommonfilesdir(officever:"12.0"), value:"\Microsoft Shared\Office12");
      if (hotfix_check_fversion(file:"Ogl.dll", version:"12.0.6738.5000", min_version:"12.0.0.0", path:path, bulletin:bulletin, kb:'3085616', product:"Microsoft Office 2007 SP3") == HCF_OLDER)
         vuln++;
    }
  }

  # Word Viewer
  wvinst = get_kb_list("SMB/Office/WordViewer/*/ProductPath");
  if (!empty_or_null(wvinst))
  {
    foreach wvkb (keys(wvinst))
    {
      if ("11.0" >!< wvkb)
        continue;
      # Delete exe part
      path = ereg_replace(pattern:"[Ww]ordview\.exe$", replace:'', string:get_kb_item(wvkb)); 
      if (hotfix_check_fversion(file:"gdiplus.dll", version:"11.0.8422.0", min_version:"11.0.0.0", path:path, bulletin:bulletin, kb:'3114478', product:"Microsoft Word Viewer") == HCF_OLDER)
        vuln++;
    }
  }
}

# Lync checks
function perform_lync_checks()
{
  local_var lync_count, lync_installs, lync_install;

  lync_count = get_install_count(app_name:"Microsoft Lync");

  # Nothing to do
  if (int(lync_count) <= 0)
    return;

  lync_installs = get_installs(app_name:"Microsoft Lync");
  foreach lync_install (lync_installs[1])
  {
    #if ("Live Meeting 2007 Console" >< lync_install["Product"])
    #{
    #  if (hotfix_check_fversion(file:"pubutil.dll", version:"8.0.6362.249", min_version:"8.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"3115875", product:"Live Meeting 2007 Console") == HCF_OLDER)
    #    vuln++;
    #}
    if (lync_install["version"] =~ "^4\.0\." && "Server" >!< lync_install["Product"])
    {
      # Lync 2010
      if ("Attendee" >!< lync_install["Product"])
      {
        if (hotfix_check_fversion(file:"communicator.exe", version:"4.0.7577.4486", min_version:"4.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"3115875", product:"Microsoft Lync 2010") == HCF_OLDER)
          vuln++;
      }
      # Lync 2010 Attendee
      else if ("Attendee" >< lync_install["Product"])
      {
        if ("user level" >< tolower(lync_install["Product"])) # User
        {
          if (hotfix_check_fversion(file:"MeetingJoinAxAOC.DLL", version:"4.0.7577.4486", min_version:"4.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"3115872", product:lync_install["Product"]) == HCF_OLDER)
            vuln++;
        }
        else # Admin
        {
          if (hotfix_check_fversion(file:"MeetingJoinAxAOC.DLL", version:"4.0.7577.4486", min_version:"4.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"3115873", product:lync_install["Product"]) == HCF_OLDER)
            vuln++;
        }
      }
    }
    # Lync 2013
    else if (lync_install["version"] =~ "^15\.0\." && "Server" >!< lync_install["Product"])
    {
      if (hotfix_check_fversion(file:"Lync.exe", version:"15.0.4779.1001", min_version:"15.0.4569.1503", path:lync_install["path"], bulletin:bulletin, kb:"3101496", product:"Microsoft Lync 2013 (Skype for Business)") == HCF_OLDER)
        vuln++;
    }
    # Skype for Business 2016
    else if (lync_install["version"] =~ "^16\.0\." && "Server" >!< lync_install["Product"])
    {
      if (hotfix_check_fversion(file:"Lync.exe", version:"16.0.4312.1000", channel:"MSI", channel_product:"Lync", path:lync_install["path"], bulletin:bulletin, kb:"3085634", product:"Skype for Business 2016") == HCF_OLDER)
        vuln++;
      if (hotfix_check_fversion(file:"Lync.exe", version:"16.0.6001.1043", channel:"Current", channel_product:"Lync", path:lync_install["path"], bulletin:bulletin, kb:"3085634", product:"Skype for Business 2016") == HCF_OLDER)
        vuln++;
    }
  }
}

# Silverlight Check
function perform_silverlight_checks()
{
  local_var slver, report, path;

  slver = get_kb_item("SMB/Silverlight/Version");
  if (slver && slver =~ "^5\." && ver_compare(ver:slver, fix:"5.1.41105.0",strict:FALSE) == -1)
  {
    path = get_kb_item("SMB/Silverlight/Path");
    if (isnull(path)) path = 'n/a';

    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + slver +
      '\n  Fixed version     : 5.1.41105.0' +
      '\n';
    hotfix_add_report(report,bulletin:bulletin, kb:"3106614");
    vuln += 1;
  }
}

perform_windows_checks();
perform_dotnet_checks();
perform_office_checks();
perform_lync_checks();
perform_silverlight_checks();

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
