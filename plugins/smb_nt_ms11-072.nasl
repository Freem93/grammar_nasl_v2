#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56175);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2015/04/23 21:35:41 $");

  script_cve_id(
    "CVE-2011-1986",
    "CVE-2011-1987",
    "CVE-2011-1988",
    "CVE-2011-1989",
    "CVE-2011-1990"
  );
  script_bugtraq_id(49476, 49477, 49478, 49517, 49518);
  script_osvdb_id(75383, 75384, 75385, 75386, 75387);
  script_xref(name:"MSFT", value:"MS11-072");

  script_name(english:"MS11-072: Vulnerabilities in Microsoft Excel Could Allow Remote Code Execution (2587505)");
  script_summary(english:"Checks versions of Excel, oart.dll, oartconv.dll, etc");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Office.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of Microsoft Office,
Excel, or a related product that is affected by several
vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Excel file, he could leverage this issue to execute
arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-280/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-281/");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-072");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2003, 2007, 2010,
Excel Viewer, Office Compatability Pack, Excel Services, and Excel Web
App.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel:2007");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel:2010");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_nt_ms02-031.nasl", "office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}


include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");
include("audit.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS11-072';
kbs = make_list("2553070", "2553072", "2553073", "2553074", "2553075", "2553089", "2553090", "2553091", "2553093", "2553094", "2553095", "2553096");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);



info = "";
vuln = FALSE;


# Excel.
installs = get_kb_list("SMB/Office/Excel/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/Excel/' - '/ProductPath';
    path = installs[install];
    if (isnull(path)) path = 'n/a';

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    # Excel 2010.
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (
      (!isnull(office_sp) && (office_sp == 0 || office_sp == 1)) &&
      (
        (ver[0] == 14 && ver[1] == 0 && ver[2] < 6106) ||
        (ver[0] == 14 && ver[1] == 0 && ver[2] == 6106 && ver[3] < 5005)
      )
    )
    {
      info =
        '\n  Product           : Excel 2010' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 14.0.6106.5005\n';
      hotfix_add_report(info, bulletin:bulletin, kb:'2553070');
     }
    # Excel 2007.
    office_sp = get_kb_item("SMB/Office/2007/SP");
    if (
      (!isnull(office_sp) && office_sp == 2) &&
      (
        (ver[0] == 12 && ver[1] == 0 && ver[2] < 6565) ||
        (ver[0] == 12 && ver[1] == 0 && ver[2] == 6565 && ver[3] < 5003)
      )
    )
    {
      info =
        '\n  Product           : Excel 2007' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 12.0.6565.5003\n';
      hotfix_add_report(info, bulletin:bulletin, kb:'2553073');
    }
    # Excel 2003.
    office_sp = get_kb_item("SMB/Office/2003/SP");
    if ((!isnull(office_sp) && office_sp == 3) && (ver[0] == 11 && ver[1] == 0 && ver[2] < 8341))
    {
      info =
        '\n  Product           : Excel 2003' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 11.0.8341.0\n';
      hotfix_add_report(info, bulletin:bulletin, kb:'2553072');
    }
  }
}


# Excel Viewer.
installs = get_kb_list("SMB/Office/ExcelViewer/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/ExcelViewer/' - '/ProductPath';
    path = installs[install];
    if (isnull(path)) path = 'n/a';

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    # Excel Viewer.
    if (
      ver[0] == 12 && ver[1] == 0 &&
      (
        ver[2] < 6565 ||
        (ver[2] == 6565 && ver[3] < 5000)
      )
    )
    {
      info =
        '\n  Product           : Excel Viewer' +
        '\n  File              : '+ path +
        '\n  Installed version : '+ version +
        '\n  Fixed version     : 12.0.6565.5000\n';
      hotfix_add_report(info, bulletin:bulletin, kb:'2553075');
    }
  }
}


# 2007 Microsoft Office system and the Microsoft Office Compatibility Pack.
installs = get_kb_list("SMB/Office/ExcelCnv/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/ExcelCnv/' - '/ProductPath';
    path = installs[install];
    if (isnull(path)) path = 'n/a';

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    # 2007 Office system and the Office Compatibility Pack.
    if (
      ver[0] == 12 && ver[1] == 0 &&
      (
        ver[2] < 6565 ||
        (ver[2] == 6565 && ver[3] < 5003)
      )
    )
    {
      info =
        '\n  Product           : 2007 Office system and the Office Compatibility Pack' +
        '\n  File              : '+ path +
        '\n  Installed version : '+ version +
        '\n  Fixed version     : 12.0.6565.5003\n';
      hotfix_add_report(info, bulletin:bulletin, kb:'2553074');
    }
  }
}

# Figure out where SharePoint Server is installed or *might be* installed.
arch = get_kb_item_or_exit("SMB/ARCH");

sps2007_path = NULL;
sps2007_std = FALSE;
sps2010_path = NULL;

port    = kb_smb_transport();
login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

hcf_init = TRUE;

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

key = "SOFTWARE\Microsoft\Office Server\12.0";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallPath");
  if (!isnull(item))
  {
    sps2007_path = item[1];
    sps2007_path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:sps2007_path);
  }

  item = RegQueryValue(handle:key_h, item:"OfficeServerPremium");
  if (!isnull(item))
  {
    office_server_premium = item[1];
    if (office_server_premium == 0) sps2007_std = TRUE;
  }

  RegCloseKey(handle:key_h);
}
if (isnull(sps2007_path)) sps2007_path = hotfix_get_programfilesdir() + "\Microsoft Office Servers\12.0";

key = "SOFTWARE\Microsoft\Office Server\14.0";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallPath");
  if (!isnull(item))
  {
    sps2010_path = item[1];
    sps2010_path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:sps2010_path);
  }

  RegCloseKey(handle:key_h);
}
if (isnull(sps2010_path)) sps2010_path = hotfix_get_programfilesdir() + "\Microsoft Office Servers\14.0";

RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);


# Excel Web App 2010.
#
# nb: webapp2010_path must be defined before 'sps2010_path' is updated.
webapp2010_path = sps2010_path + "\WebServices\ConversionService\Bin\Converter\1003";
if (
  hotfix_check_fversion(path:webapp2010_path, file:"Xlsrvintl.dll", version:"14.0.6106.5005", min_version:"14.0.0.0", bulletin:bulletin, kb:'2553095') == HCF_OLDER
) vuln = TRUE;


# Excel Services in SharePoint Server 2007.
sps2007_path += "\bin";
if (
  sps2007_std == FALSE &&
  hotfix_check_fversion(path:sps2007_path, file:"Xlsrv.dll", version:"12.0.6565.5000", min_version:"12.0.0.0", bulletin:bulletin, kb:'2553093') == HCF_OLDER
) vuln = TRUE;

# Excel Services in SharePoint Server 2010
sps2010_path += "\bin";
if (
    hotfix_check_fversion(path:sps2010_path, file:"Xlsrv.dll", version:"14.0.6106.5005", min_version:"14.0.0.0", bulletin:bulletin, kb:'2553094') == HCF_OLDER
) vuln = TRUE;


# Office
office_ver = hotfix_check_office_version();
x86_path = hotfix_get_commonfilesdir();
x64_path = hotfix_get_programfilesdirx86();

# - Office 2010
if (office_ver && office_ver['14.0'])
{
  office_sp = get_kb_item("SMB/Office/2010/SP");
  if (!isnull(office_sp) && office_sp <= 1)
  {
    kb = '2553091';
    if (
      (x86_path && hotfix_is_vulnerable(file:"Oart.dll", version:"14.0.6106.5005", min_version:'14.0.0.0', path:x86_path + "\Microsoft Shared\Office14", bulletin:bulletin, kb:kb)) ||
      (x64_path && hotfix_is_vulnerable(file:"Oart.dll", arch:"x64", version:"14.0.6106.5005", min_version:'14.0.0.0', path:x64_path + "\Common Files\Microsoft Shared\Office14", bulletin:bulletin, kb:kb))
    ) vuln = TRUE;

    kb = '2553096';
    if (
      (x86_path && hotfix_is_vulnerable(file:"Oartconv.dll", version:"14.0.6106.5005", min_version:'14.0.0.0', path:x86_path + "\Microsoft Shared\Office14", bulletin:bulletin, kb:kb)) ||
      (x64_path && hotfix_is_vulnerable(file:"Oartconv.dll", arch:"x64", version:"14.0.6106.5005", min_version:'14.0.0.0', path:x64_path + "\Common Files\Microsoft Shared\Office14", bulletin:bulletin, kb:kb))
    ) vuln = TRUE;
  }
}
# - Office 2007
#
# nb: footnote #1 in MS11-072 says KB2553074 needs to be installed
#     too with Office 2007, but we checked for that earlier in the
#     plugin.
else if (office_ver && office_ver['12.0'])
{
  office_sp = get_kb_item("SMB/Office/2007/SP");
  if (!isnull(office_sp) && office_sp == 2)
  {
    kb = '2553089';
    if (
      (x86_path && hotfix_is_vulnerable(file:"Oart.dll", version:"12.0.6565.5000", min_version:'12.0.0.0', path:x86_path + "\Microsoft Shared\Office12", bulletin:bulletin, kb:kb)) ||
      (x64_path && hotfix_is_vulnerable(file:"Oart.dll", arch:"x64", version:"12.0.6565.5000", min_version:'12.0.0.0', path:x64_path + "\Common Files\Microsoft Shared\Office12", bulletin:bulletin, kb:kb))
    ) vuln = TRUE;

    kb = '2553090';
    if (
      (x86_path && hotfix_is_vulnerable(file:"Oartconv.dll", version:"12.0.6565.5000", min_version:'12.0.0.0', path:x86_path + "\Microsoft Shared\Office12", bulletin:bulletin, kb:kb)) ||
      (x64_path && hotfix_is_vulnerable(file:"Oartconv.dll", arch:"x64", version:"12.0.6565.5000", min_version:'12.0.0.0', path:x64_path + "\Common Files\Microsoft Shared\Office12", bulletin:bulletin, kb:kb))
    ) vuln = TRUE;
  }
}


if (info || vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
}
else audit(AUDIT_HOST_NOT, 'affected');
