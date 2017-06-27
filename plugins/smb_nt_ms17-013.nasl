#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97794);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/26 23:57:36 $");

  script_cve_id(
    "CVE-2017-0001",
    "CVE-2017-0005",
    "CVE-2017-0014",
    "CVE-2017-0025",
    "CVE-2017-0038",
    "CVE-2017-0047",
    "CVE-2017-0060",
    "CVE-2017-0061",
    "CVE-2017-0062",
    "CVE-2017-0063",
    "CVE-2017-0073",
    "CVE-2017-0108"
  );
  script_bugtraq_id(
    96013,
    96023,
    96033,
    96034,
    96057,
    96626,
    96637,
    96638,
    96643,
    96713,
    96715,
    96722
  );
  script_osvdb_id(
    152178,
    153742,
    153743,
    153744,
    153745,
    153746,
    153747,
    153748,
    153749,
    153750,
    153751,
    153752
  );
  script_xref(name:"MSFT", value:"MS17-013");
  script_xref(name:"MSKB", value:"3127945");
  script_xref(name:"MSKB", value:"3127958");
  script_xref(name:"MSKB", value:"3141535");
  script_xref(name:"MSKB", value:"3172539");
  script_xref(name:"MSKB", value:"3178653");
  script_xref(name:"MSKB", value:"3178656");
  script_xref(name:"MSKB", value:"3178688");
  script_xref(name:"MSKB", value:"3178693");
  script_xref(name:"MSKB", value:"4010096");
  script_xref(name:"MSKB", value:"4010299");
  script_xref(name:"MSKB", value:"4010300");
  script_xref(name:"MSKB", value:"4010303");
  script_xref(name:"MSKB", value:"4010304");
  script_xref(name:"MSKB", value:"4012212");
  script_xref(name:"MSKB", value:"4012213");
  script_xref(name:"MSKB", value:"4012214");
  script_xref(name:"MSKB", value:"4012215");
  script_xref(name:"MSKB", value:"4012216");
  script_xref(name:"MSKB", value:"4012217");
  script_xref(name:"MSKB", value:"4012497");
  script_xref(name:"MSKB", value:"4017018");
  script_xref(name:"MSKB", value:"4012584");
  script_xref(name:"MSKB", value:"4012606");
  script_xref(name:"MSKB", value:"4013198");
  script_xref(name:"MSKB", value:"4013429");
  script_xref(name:"MSKB", value:"4013867");
  script_xref(name:"IAVA", value:"2017-A-0063");

  script_name(english:"MS17-013: Security Update for Microsoft Graphics Component (4013075)");
  script_summary(english:"Checks the version of win32k.sys or the installed rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple vulnerabilities :

  - Multiple elevation of privilege vulnerabilities exist in
    the Windows Graphics Device Interface (GDI) component
    due to improper handling of objects in memory. A local
    attacker can exploit these vulnerabilities, via a
    specially crafted application, to execute arbitrary code
    in kernel mode. (CVE-2017-0001, CVE-2017-0005,
    CVE-2017-0025, CVE-2017-0047)

  - Multiple remote code execution vulnerabilities exist in
    the Windows Graphics component due to improper handling
    of objects in memory. An unauthenticated, remote
    attacker can exploit these vulnerabilities, by
    convincing a user to visit a specially crafted web page
    or open a specially crafted document, to execute
    arbitrary code. (CVE-2017-0014, CVE-2017-0108)

  - An information disclosure vulnerability exists in the
    Windows Graphics Device Interface (GDI) component due to
    improper handling of objects in memory. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to visit a specially crafted web page
    or open a specially crafted document, to disclose the
    contents of memory. (CVE-2017-0038)

  - Multiple information disclosure vulnerabilities exist in
    the Windows Graphics Device Interface (GDI) component
    due to improper handling of memory addresses. A local
    attacker can exploit these vulnerabilities, via a
    specially crafted application, to disclose sensitive
    information. (CVE-2017-0060, CVE-2017-0062,
    CVE-2017-0073)

  - Multiple information disclosure vulnerabilities exist in
    the Color Management Module (ICM32.dll) due to improper
    handling of objects in memory. An unauthenticated,
    remote attacker can exploit this, by convincing a user
    to visit a specially crafted web page, to disclose
    sensitive information and bypass usermode Address Space
    Layout Randomization (ASLR). (CVE-2017-0061,
    CVE-2017-0063)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms17-013");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, 10, and 2016. Additionally,
Microsoft has released a set of patches for Office 2007, Office 2010,
Word Viewer, Skype for Business 2016, Lync 2010, Lync 2010 Attendee,
Lync 2013, Lync Basic 2013, Live Meeting 2007 Console, and Silverlight
5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:live_meeting_console");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync_basic");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync_attendee");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:skype_for_business");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:silverlight");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("silverlight_detect.nasl",
                      "microsoft_lync_server_installed.nasl",
                      "smb_hotfixes.nasl",
                      "office_installed.nasl",
                      "ms_bulletin_checks_possible.nasl",
                      "smb_check_rollup.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

kbs = make_list('3127945',
                '3127958',
                '3141535',
                '3172539',
                '3178653',
                '3178656',
                '3178688',
                '3178693',
                '4010096',
                '4010299',
                '4010300',
                '4010303',
                '4010304',
                '4012212',
                '4012213',
                '4012214',
                '4012215',
                '4012216',
                '4012217',
                '4012497',
                '4017018',
                '4012584',
                '4012606',
                '4013198',
                '4013429',
                '4013867'
);

bulletin = 'MS17-013';
common_office_path = '';

function perform_office_checks() {
  local_var office_vers, office_sp, common_path, path, prod, kb, vuln;
  office_vers = hotfix_check_office_version();
  vuln = 0;
  # Office 2003 checks
  if (office_vers["11.0"])
  {
    local_var wvchecks = {
      "11.0": {"version" : "11.0.8440.0",
               "kb"      : "3178693"}
    };
    if (hotfix_check_office_product(product:"WordViewer",
                                    display_name:"Word Viewer",
                                    checks:wvchecks,
                                    bulletin:bulletin))
      vuln++;                       
    common_path = hotfix_get_officecommonfilesdir(officever:"11.0");
    path = hotfix_append_path(path:common_path, value:"Microsoft Shared\Office12");
    if (hotfix_check_fversion(file:"usp10.dll",
                              version:"1.0626.6002.24058",
                              min_version:"1.0.0.0",
                              path:path,
                              bulletin:bulletin,
                              kb:"3178653",
                              product:"Word Viewer"))
      vuln++;
  }
  # Office 2007 checks
  if (office_vers["12.0"])
  {
    office_sp = get_kb_item("SMB/Office/2007/SP");
    if (!isnull(office_sp) && office_sp == 3)
    {
      prod = "Microsoft Office 2007 SP3";
      common_path = hotfix_get_officecommonfilesdir(officever:"12.0");
      path = hotfix_append_path(path:common_path, value:"Microsoft Shared\Office12");
      if (hotfix_check_fversion(file:"ogl.dll",
                                version:"12.0.6764.5000",
                                min_version:"12.0.0.0",
                                path:path,
                                bulletin:bulletin,
                                kb:"3127945",
                                product:prod) == HCF_OLDER ||
          hotfix_check_fversion(file:"usp10.dll",
                                version:"1.0626.6002.24058",
                                min_version:"1.0.0.0",
                                path:path,
                                bulletin:bulletin,
                                kb:"3141535",
                                product:prod) == HCF_OLDER)
        vuln++;
      path = common_path + "\Live Meeting 8\Addins\";
      if (hotfix_check_fversion(file:"LMAddins.dll", 
                                version:"8.0.6362.264",
                                min_version:"8.0.0.0",
                                path:path,
                                bulletin:bulletin,
                                kb:"4010304",
                                product: "Live Meeting 2007 Add-in") == HCF_OLDER)
        vuln ++;
    } # end of SP3 checks
  } # end of Office 2007 checks
  if (office_vers["14.0"])
  {
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (!isnull(office_sp) && office_sp == 2)
    {
      prod = "Microsoft Office 2010 SP2";
      common_path = hotfix_get_officecommonfilesdir(officever:"14.0");
      path = hotfix_append_path(path:common_path, value:"Microsoft Shared\Office14");
      if ((hotfix_check_fversion(file:"ogl.dll",
                                version:"14.0.7179.5000",
                                min_version:"14.0.0.0",
                                path:path,
                                bulletin:bulletin,
                                kb:"3127958",
                                product:prod) == HCF_OLDER) ||
          (hotfix_check_fversion(file:"usp10.dll",
                                version:"1.0626.7601.23668",
                                min_version:"1.0.0.0",
                                path:path,
                                bulletin:bulletin,
                                kb:"3178688",
                                product:prod) == HCF_OLDER))
        vuln++;
    } # end sp2 

  } # end office 2010`
  return vuln;
}

function lync_is_vuln()
{
  local_var vuln, lync_count, lync_installs, lync_install;
  local_var lync = "Microsoft Lync";
  lync_count = get_install_count(app_name:lync);
  vuln = 0;
  if (int(lync_count) <= 0)
    return FALSE;

  lync_installs = get_installs(app_name:lync);
  
  foreach (lync_install in lync_installs[1])
  {
     if (("Live Meeting 2007 Console" >< lync_install["Product"]) &&
         (hotfix_check_fversion(file:"pubutil.dll",
                                version:"8.0.6362.264",
                                min_version:"8.0.0.0",
                                path:lync_install["path"],
                                bulletin:bulletin,
                                kb:"4010303",
                                product:"Live Meeting 2007 Console") == HCF_OLDER))
       vuln++;
        # the same check works for both Microsoft Lync 2010 and 
        # Microsoft Lync 2010 Attendee (Ocpptview.dll, v.4.0.7577.4525)
     if (("Microsoft Lync 2010" >< lync_install["Product"]) &&
         (hotfix_check_fversion(file:"Ocpptview.dll",
                                 version:"4.0.7577.4525",
                                 min_version:"4.0.0.0",
                                 path:lync_install["path"],
                                 kb:"4010299",
                                 product:"Microsoft Lync 2010") == HCF_OLDER))
       vuln++;
     if ((lync_install["version"] =~ "^4\.0\." && "Server" >!< lync_install["Product"] 
           && "Attendee" >< lync_install["Product"]) &&
         (hotfix_check_fversion(file:"MeetingJoinAxAOC.DLL",
                                 version:"4.0.7577.4525",
                                 min_version:"4.0.0.0",
                                 path:lync_install["path"],
                                 kb:"4010300",
                                 product:"Microsoft Lync 2010 Attendee") == HCF_OLDER))
       vuln++;
     if("Microsoft Lync" >< lync_install["Product"] && lync_install["version"] =~ "^15\." &&
         (hotfix_check_fversion(file:"Lync.exe",
                                 version:"15.0.4911.1000",
                                 min_version:"15.0.0.0",
                                 path:lync_install["path"],
                                 kb:"3172539",
                                 product:"Microsoft Lync 2013") == HCF_OLDER)) 
       vuln++;
        # Skype for business
     if ((lync_install["version"] =~ "^16\.0\." && "Server" >!< lync_install["Product"]) &&
         (hotfix_check_fversion(file:"Lync.exe",
                                 version:"16.0.4510.1000",
                                 min_version:"16.0.0.0",
                                 path:lync_install["path"],
                                 kb:"3178656",
                                 product:"Skype for Business 2016") == HCF_OLDER))
       vuln++;
  }

  return vuln;
}

function silverlight_is_vuln()
{
  local_var silver, path, report, fix;
  local_var vuln = 0;
  silver = get_kb_item("SMB/Silverlight/Version");
  if (!isnull(silver) && silver =~ "^5\.")
  {
    fix = "5.1.50905.0";
    if (ver_compare(ver:silver, fix:fix) == -1)
    {
      path = get_kb_item("SMB/Silverlight/Path");
      if (isnull(path)) path = 'n/a';

      report =
        '\n  Path              : ' + path +
        '\n  Installed version : ' + silver +
        '\n  Fixed version     : ' + fix +
        '\n';
      hotfix_add_report(report, bulletin:bulletin, kb:"4013867");
      vuln++;
    }
  }
  return vuln;
}

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

# double check this
if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# Windows 8 EOL
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = 0;
vuln += lync_is_vuln();
vuln += perform_office_checks();
vuln += silverlight_is_vuln();

if (
  # Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Gdi32.dll", version:"6.0.6002.24081", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"4017018") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Gdi32.dll", version:"6.0.6002.19758", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"4017018") ||
  hotfix_is_vulnerable(os:'6.0', sp:2, file:'Icm32.dll', version:'6.0.6002.24065', min_version:'6.0.6002.23000', dir:"\system32", bulletin:bulletin, kb:"4012584") ||
  hotfix_is_vulnerable(os:'6.0', sp:2, file:'Icm32.dll', version:'6.0.6002.19741', min_version:'6.0.6002.18000', dir:"\system32", bulletin:bulletin, kb:"4012584") ||
  hotfix_is_vulnerable(os:'6.0', sp:2, file:'Win32k.sys', version:'6.0.6002.24065', min_version:'6.0.6002.23000', dir:"\system32", bulletin:bulletin, kb:"4012497") ||
  hotfix_is_vulnerable(os:'6.0', sp:2, file:'Win32k.sys', version:'6.0.6002.19741', min_version:'6.0.6002.18000', dir:"\system32", bulletin:bulletin, kb:"4012497") ||

  # 7 SP1 / 2008 R2 SP1
  smb_check_rollup(os:"6.1",
                   sp:1,
                   rollup_date:"03_2017",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(4012212, 4012215)) ||

  # 8.1 / 2012 R2
  smb_check_rollup(os:"6.3",
                   sp:0,
                   rollup_date: "03_2017",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(4012213, 4012216)) ||
  # 2012
  smb_check_rollup(os:"6.2",
                   sp:0,
                   rollup_date: "03_2017",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(4012214, 4012217)) ||
  # 2012 R2
  smb_check_rollup(os:"6.3",
                   sp:0,
                   rollup_date: "03_2017",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(4012213, 4012216)) ||
  # 10 (1507)
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"10240",
                   rollup_date: "03_2017",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(4012606)) ||
  # 10 (1511)
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"10586",
                   rollup_date: "03_2017",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(4013198)) ||
  # 10 (1607)
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"14393",
                   rollup_date: "03_2017",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(4013429)) ||
  vuln
)
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
