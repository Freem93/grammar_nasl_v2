#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85877);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/16 14:22:07 $");

  script_cve_id(
    "CVE-2015-2506",
    "CVE-2015-2507",
    "CVE-2015-2508",
    "CVE-2015-2510",
    "CVE-2015-2511",
    "CVE-2015-2512",
    "CVE-2015-2517",
    "CVE-2015-2518",
    "CVE-2015-2527",
    "CVE-2015-2529",
    "CVE-2015-2546"
  );
  script_bugtraq_id(
    76563,
    76589,
    76591,
    76592,
    76593,
    76597,
    76599,
    76602,
    76606,
    76607,
    76608
  );
  script_osvdb_id(
    127187,
    127188,
    127189,
    127190,
    127191,
    127192,
    127193,
    127195,
    127196,
    127217
  );
  script_xref(name:"MSFT", value:"MS15-097");
  script_xref(name:"IAVA", value:"2015-A-0212");

  script_name(english:"MS15-097: Vulnerabilities in Microsoft Graphics Component Could Allow Remote Code Execution (3089656)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple vulnerabilities :

  - An elevation of privilege vulnerability exists in the
    Windows Adobe Type Manager Library due to improper
    handling of specially crafted OpenType fonts. An
    authenticated, remote attacker can exploit this
    vulnerability, via a specially crafted application, to
    elevate privileges and execute arbitrary code.
    (CVE-2015-2506)

  - Multiple elevation of privilege vulnerabilities exist in
    the Windows Adobe Type Manager Library due to improper
    handling of objects in memory. A local attacker can
    exploit these vulnerabilities, via a specially crafted
    application, to execute arbitrary code. (CVE-2015-2507,
    CVE-2015-2508, CVE-2015-2512)
  
  - A remote code execution vulnerability exists in
    components of Windows, Office, and Lync due to improper
    handling of specially crafted OpenType fonts. An
    unauthenticated, remote attacker can exploit this
    vulnerability by convincing a user to open a file or
    visit a website containing specially crafted OpenType
    fonts, resulting in execution of arbitrary code in the
    context of the current user. (CVE-2015-2510)

  - Multiple elevation of privilege vulnerabilities exist in
    the Windows kernel-mode driver due to improper handling
    of objects in memory. A local attacker can exploit these
    vulnerabilities, via a specially crafted application, to
    execute arbitrary code in kernel mode. (CVE-2015-2511,
    CVE-2015-2517, CVE-2015-2518, CVE-2015-2546)

  - An elevation of privilege vulnerability exists in the
    Windows kernel-mode driver due to improper validation
    and enforcement of integrity levels during certain
    process initialization scenarios. A local attacker can
    exploit this vulnerability, via a specially crafted
    application, to execute arbitrary code in kernel mode.
    (CVE-2015-2527)

  - A security feature bypass vulnerability exists due to
    a failure by the Windows kernel to properly initialize a
    memory address. A local attacker can exploit this, via a
    specially crafted application, to bypass Kernel Address
    Space Layout Randomization (KASLR) and retrieve the base
    address of the kernel driver. (CVE-2015-2529)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/ms15-097.aspx");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, RT, 2012, 8.1, RT 8.1, 2012 R2, and 10. Additionally,
Microsoft has released a set of patches for Office 2007, Office 2010,
Lync 2010, Lync 2010 Attendee, Lync 2013 (Skype for Business), Lync
Basic 2013, and Live Meeting 2007.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:live_meeting_console");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync_basic");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:skype_for_business");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "office_installed.nasl", "microsoft_lync_server_installed.nasl");
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
bulletin = 'MS15-097';

kbs = make_list(
  '3085529', # Office 2010 SP 2
  '3085546', # Office 2007 SP 3
  '3085500', # Microsoft Lync 2013 (Skype for Business)
  '3081087', # Microsoft Lync 2010
  '3081088', # Microsoft Lync 2010 Attendee
  '3081089', # Microsoft Lync 2010 Attendee (admin level install)
  '3081090', # Microsoft Live Meeting 2007
  '3087039', # Windows (all but 10)
  '3087135', # Windows (all but 10)
  '3081455'  # Windows 10
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
  # KB 3081455
  if (
    # Windows 10
    hotfix_is_vulnerable(os:"10", sp:0, file:"atmfd.dll", version:"5.1.2.246", dir:"\system32", bulletin:bulletin, kb:'3081455')
  )
    vuln++;

  # KB 3087039
  if (
    # Windows 8.1 / Windows Server 2012 R2
    hotfix_is_vulnerable(os:"6.3", sp:0, file:"atmfd.dll", version:"5.1.2.246", dir:"\system32", bulletin:bulletin, kb:'3087039') ||

    # Windows 8 / Windows Server 2012
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"atmfd.dll", version:"5.1.2.246", dir:"\system32", bulletin:bulletin, kb:'3087039') ||

    # Windows 7 and Windows Server 2008 R2
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"atmfd.dll", version:"5.1.2.246", dir:"\system32", bulletin:bulletin, kb:'3087039') ||

    # Vista / Windows 2008
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"atmfd.dll", version:"5.1.2.246", dir:"\system32", bulletin:bulletin, kb:'3087039')
  )
    vuln++;

  # KB 3087135
  if (
    # Vista / Windows 2008
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"gdiplus.dll", version:"5.2.6002.19466", min_version:"5.2.6002.0", dir:"\system32", bulletin:bulletin, kb:'3087135') ||
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"gdiplus.dll", version:"5.2.6002.23775", min_version:"5.2.6002.20000", dir:"\system32", bulletin:bulletin, kb:'3087135') ||

    # Vista / Windows 2008
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"gdiplus.dll", version:"6.0.6002.19466", min_version:"6.0.6002.0", dir:"\system32", bulletin:bulletin, kb:'3087135') ||
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"gdiplus.dll", version:"6.0.6002.23775", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:'3087135')
  )
    vuln++;
}

# KB 3085546 / KB 3085529 (Office Checks)
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
      if (hotfix_check_fversion(file:"Ogl.dll", version:"14.0.7157.5000", min_version:"14.0.0.0", path:path, bulletin:bulletin, kb:"3085529", product:"Microsoft Office 2010 SP2") == HCF_OLDER)
        vuln++;
    }
  }

  if (office_versions["12.0"])
  {
    office_sp = get_kb_item("SMB/Office/2007/SP");
    if (office_sp == 3)
    {
      path = hotfix_append_path(path:hotfix_get_officecommonfilesdir(officever:"12.0"), value:"\Microsoft Shared\Office12");
      if (hotfix_check_fversion(file:"Ogl.dll", version:"12.0.6728.5000", min_version:"12.0.0.0", path:path, bulletin:bulletin, kb:'3085546', product:"Microsoft Office 2007 SP3") == HCF_OLDER)
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
        if (hotfix_check_fversion(file:"pubutil.dll", version:"8.0.6362.239", min_version:"8.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"3081090", product:"Live Meeting 2007 Console") == HCF_OLDER)
          vuln++;
      }
      else if (lync_install["version"] =~ "^4\.0\." && "Server" >!< lync_install["Product"])
      {
        if ("Attendee" >!< lync_install["Product"])
       {
          if (hotfix_check_fversion(file:"communicator.exe", version:"4.0.7577.4478", min_version:"4.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"3081087", product:"Microsoft Lync 2010") == HCF_OLDER)
            vuln++;
        }
        else if ("Attendee" >< lync_install["Product"])
        {
          if ("user level" >< tolower(lync_install["Product"]))
          {
            if (hotfix_check_fversion(file:"MeetingJoinAxAOC.DLL", version:"4.0.7577.4478", min_version:"4.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"3081088", product:lync_install["Product"]) == HCF_OLDER)
              vuln++;
          }
          else
          {
            if (hotfix_check_fversion(file:"MeetingJoinAxAOC.DLL", version:"4.0.7577.4478", min_version:"4.0.0.0", path:lync_install["path"], bulletin:bulletin, kb:"3081089", product:lync_install["Product"]) == HCF_OLDER)
              vuln++;
          }
        }
      }
      else if (lync_install["version"] =~ "^15\.0\." && "Server" >!< lync_install["Product"])
      {
        if (hotfix_check_fversion(file:"Lync.exe", version:"15.0.4753.1000", min_version:"15.0.4569.1503", path:lync_install["path"], bulletin:bulletin, kb:"3085500", product:"Microsoft Lync 2013 (Skype for Business)") == HCF_OLDER)
          vuln++;
      }
    }
  }
}

perform_windows_checks();
perform_office_checks();
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
