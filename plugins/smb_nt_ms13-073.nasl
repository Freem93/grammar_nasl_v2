#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69833);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/01/28 22:37:18 $");

  script_cve_id("CVE-2013-1315", "CVE-2013-3158", "CVE-2013-3159");
  script_bugtraq_id(62167, 62219, 62225);
  script_osvdb_id(97131, 97134, 97135);
  script_xref(name:"MSFT", value:"MS13-073");
  script_xref(name:"IAVA", value:"2013-A-0171");

  script_name(english:"MS13-073: Vulnerabilities in Microsoft Excel Could Allow Remote Code Execution (2858300))");
  script_summary(english:"Checks versions of Excel, Excelcnv.exe, and Xlview.exe.");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to execute arbitrary code on the remote host through
Microsoft Excel.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of Microsoft Excel that
is affected by the following vulnerabilities :

  - Two memory corruption vulnerabilities exist due to the
    way the application handles objects in memory when
    parsing Office files. (CVE-2013-1315 / CVE-2013-3158)

  - An information disclosure vulnerability exists due to
    the way the application parses XML files containing
    external entities. (CVE-2013-3159)

If an attacker can trick a user on the affected host into opening a
specially crafted Excel file, it may be possible to leverage these
issues to read arbitrary files on the target system or execute
arbitrary code, subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-073");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Excel 2003, 2007, 2010,
2013, Excel Viewer, and Office Compatibility Pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS13-073";
kbs = make_list(
  2858300, 2760583, 2760588, 2760590, 2760597, 2768017, 2810048
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

info = "";
vuln = FALSE;

######################################################################
# Excel
######################################################################
installs = get_kb_list("SMB/Office/Excel/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/Excel/' - '/ProductPath';
    path = installs[install];
    if (isnull(path)) path = "n/a";

    ver = split(version, sep:".", keep:FALSE);
    for (i = 0; i < max_index(ver); i++)
      ver[i] = int(ver[i]);

    # Excel 2013.
    if (
        (ver[0] == 15 && ver[1] == 0 && ver[2] < 4535) ||
        (ver[0] == 15 && ver[1] == 0 && ver[2] == 4535 && ver[3] < 1003)
    )
    {
      vuln = TRUE;
      info =
        '\n  Product           : Excel 2013' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 15.0.4535.1003' +
        '\n';
      hotfix_add_report(info, bulletin:bulletin, kb:"2768017");
    }

    # Excel 2010.
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (
      (!isnull(office_sp) && ( (office_sp == 1) || (office_sp == 2) ) ) &&
      (
        (ver[0] == 14 && ver[1] == 0 && ver[2] < 7104) ||
        (ver[0] == 14 && ver[1] == 0 && ver[2] == 7104 && ver[3] < 5000)
      )
    )
    {
      vuln = TRUE;
      info =
        '\n  Product           : Excel 2010' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 14.0.7104.5000' +
        '\n';
      hotfix_add_report(info, bulletin:bulletin, kb:"2760597");
     }

    # Excel 2007.
    office_sp = get_kb_item("SMB/Office/2007/SP");
    if (
      (!isnull(office_sp) && (office_sp == 3)) &&
      (
        (ver[0] == 12 && ver[1] == 0 && ver[2] < 6679) ||
        (ver[0] == 12 && ver[1] == 0 && ver[2] == 6679 && ver[3] < 5000)
      )
    )
    {
      vuln = TRUE;
      info =
        '\n  Product           : Excel 2007' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 12.0.6679.5000' +
        '\n';
      hotfix_add_report(info, bulletin:bulletin, kb:"2760583");
    }

    # Excel 2003.
    office_sp = get_kb_item("SMB/Office/2003/SP");
    if ((!isnull(office_sp) && office_sp == 3) && (ver[0] == 11 && ver[1] == 0 && ver[2] < 8404))
    {
      vuln = TRUE;
      info =
        '\n  Product           : Excel 2003' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 11.0.8404.0' +
        '\n';
      hotfix_add_report(info, bulletin:bulletin, kb:"2810048");
    }
  }
}

######################################################################
# Excel Viewer
######################################################################
version = '';
installs = get_kb_list("SMB/Office/ExcelViewer/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/ExcelViewer/' - '/ProductPath';
    path = installs[install];
    if (isnull(path)) path = "n/a";

    ver = split(version, sep:".", keep:FALSE);
    for (i = 0; i < max_index(ver); i++)
      ver[i] = int(ver[i]);

    # Excel Viewer 2007 SP3.
    if (
      (ver[0] == 12 && ver[1] == 0 && ver[2] >= 6611) &&
      (
        (ver[0] == 12 && ver[1] == 0 && ver[2] < 6679) ||
        (ver[0] == 12 && ver[1] == 0 && ver[2] == 6679 && ver[3] < 5000)
      )
    )
    {
      vuln = TRUE;
      info =
        '\n  Product           : Excel Viewer' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 12.0.6679.5000' +
        '\n';
      hotfix_add_report(info, bulletin:bulletin, kb:"2760590");
      break;
    }
  }
}
x86_path = hotfix_get_commonfilesdir();
x64_path = hotfix_get_programfilesdirx86();
if (!version)
{
  kb = "2760590";
  if (
    (x86_path && hotfix_is_vulnerable(file:"Xlview.exe", version:"12.0.6679.5000", min_version:"12.0.0.0", path:x86_path + "\Microsoft Office\Office12", bulletin:bulletin, kb:kb)) ||
    (x64_path && hotfix_is_vulnerable(file:"Xlview.exe", arch:"x64", version:"12.0.6679.5000", min_version:"12.0.0.0", path:x64_path + "\Microsoft Office\Office12", bulletin:bulletin, kb:kb))
  ) vuln = TRUE;
}


######################################################################
# Microsoft Office Compatibility Pack
######################################################################
version = '';
installs = get_kb_list("SMB/Office/ExcelCnv/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/ExcelCnv/' - '/ProductPath';
    path = installs[install];
    if (isnull(path)) path = "n/a";

    ver = split(version, sep:".", keep:FALSE);
    for (i = 0; i < max_index(ver); i++)
      ver[i] = int(ver[i]);

    if (
      (ver[0] == 12 && ver[1] == 0 && ver[2] < 6679) ||
      (ver[0] == 12 && ver[1] == 0 && ver[2] == 6679 && ver[3] < 5000)
    )
    {
      info =
        '\n  Product           : 2007 Office system and the Office Compatibility Pack' +
        '\n  File              : '+ path +
        '\n  Installed version : '+ version +
        '\n  Fixed version     : 12.0.6679.5000' +
        '\n';
      hotfix_add_report(info, bulletin:bulletin, kb:"2760588");
    }
  }
}
if (!version)
{
  kb = "2760588";
  if (
    (x86_path && hotfix_is_vulnerable(file:"Excelcnv.exe", version:"12.0.6679.5000", min_version:"12.0.0.0", path:x86_path + "\Microsoft Office\Office12", bulletin:bulletin, kb:kb)) ||
    (x64_path && hotfix_is_vulnerable(file:"Excelcnv.exe", arch:"x64", version:"12.0.6679.5000", min_version:"12.0.0.0", path:x64_path + "\Microsoft Office\Office12", bulletin:bulletin, kb:kb))
  ) vuln = TRUE;
}

if (info || vuln)
{
  set_kb_item(name:"SMB/Missing/" + bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, "affected");
}
