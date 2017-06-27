#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62908);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/11/03 21:08:35 $");

  script_cve_id(
    "CVE-2012-1885",
    "CVE-2012-1886",
    "CVE-2012-1887",
    "CVE-2012-2543"
  );
  script_bugtraq_id(56425, 56426, 56430, 56431);
  script_osvdb_id(87270, 87271, 87272, 87273);
  script_xref(name:"MSFT", value:"MS12-076");

  script_name(english:"MS12-076: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (2720184)");
  script_summary(english:"Checks versions of Excel, Excelcnv.exe, and Xlview.exe.");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to execute arbitrary code on the remote host through
Microsoft Excel.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of Microsoft Excel that
is affected by the following vulnerabilities :

  - A heap-based buffer overflow vulnerability exists due to
    the way the application handles memory when opening
    Excel
    files. (CVE-2012-1885)

  - A memory corruption vulnerability exists due to the way
    the application handles memory when opening Excel
    files. (CVE-2012-1886)

  - A use-after-free vulnerability exists due to the way
    the application handles memory when opening Excel
    files. (CVE-2012-1887)

  - A stack-based buffer overflow vulnerability exists due
    to the way the application handles data structures while
    parsing Excel files. (CVE-2012-2543)

If an attacker can trick a user on the affected host into opening a
specially crafted Excel file, it may be possible to leverage these
issues to execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-184/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Nov/110");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-076");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Excel 2003, 2007, 2010,
Excel Viewer, and Office Compatibility Pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

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

bulletin = "MS12-076";
kbs = make_list(
  "2597126", "2687307", "2687311", "2687313", "2687481"
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

    # Excel 2010.
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (
      (!isnull(office_sp) && office_sp == 1) &&
      (
        (ver[0] == 14 && ver[1] == 0 && ver[2] < 6126) ||
        (ver[0] == 14 && ver[1] == 0 && ver[2] == 6126 && ver[3] < 5003)
      )
    )
    {
      vuln = TRUE;
      info =
        '\n  Product           : Excel 2010' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 14.0.6126.5003' +
        '\n';
      hotfix_add_report(info, bulletin:bulletin, kb:"2597126");
     }

    # Excel 2007.
    office_sp = get_kb_item("SMB/Office/2007/SP");
    if (
      (!isnull(office_sp) && (office_sp == 2 || office_sp == 3)) &&
      (
        (ver[0] == 12 && ver[1] == 0 && ver[2] < 6665) ||
        (ver[0] == 12 && ver[1] == 0 && ver[2] == 6665 && ver[3] < 5003)
      )
    )
    {
      vuln = TRUE;
      info =
        '\n  Product           : Excel 2007' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 12.0.6665.5003' +
        '\n';
      hotfix_add_report(info, bulletin:bulletin, kb:"2687307");
    }

    # Excel 2003.
    office_sp = get_kb_item("SMB/Office/2003/SP");
    if ((!isnull(office_sp) && office_sp == 3) && (ver[0] == 11 && ver[1] == 0 && ver[2] < 8347))
    {
      vuln = TRUE;
      info =
        '\n  Product           : Excel 2003' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 11.0.8347.0' +
        '\n';
      hotfix_add_report(info, bulletin:bulletin, kb:"2687481");
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

    # Excel Viewer.
    if (
      # Excel Viewer 2007 SP2 == 12.0.6424.100
      (ver[0] == 12 && ver[1] == 0 && ver[2] >= 6424) &&
      (
        (ver[0] == 12 && ver[1] == 0 && ver[2] < 6665) ||
        (ver[0] == 12 && ver[1] == 0 && ver[2] == 6665 && ver[3] < 5003)
      )
    )
    {
      vuln = TRUE;
      info =
        '\n  Product           : Excel Viewer' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 12.0.6665.5003' +
        '\n';
      hotfix_add_report(info, bulletin:bulletin, kb:"2687313");
      break;
    }
  }
}
x86_path = hotfix_get_commonfilesdir();
x64_path = hotfix_get_programfilesdirx86();
if (!version)
{
  # Additional check if registry key is missing
  kb = "2687313";
  if (
    (x86_path && hotfix_is_vulnerable(file:"Xlview.exe", version:"12.0.6665.5003", min_version:"12.0.0.0", path:x86_path + "\Microsoft Office\Office12", bulletin:bulletin, kb:kb)) ||
    (x64_path && hotfix_is_vulnerable(file:"Xlview.exe", arch:"x64", version:"12.0.6665.5003", min_version:"12.0.0.0", path:x64_path + "\Microsoft Office\Office12", bulletin:bulletin, kb:kb))
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
      (ver[0] == 12 && ver[1] == 0 && ver[2] < 6665) ||
      (ver[0] == 12 && ver[1] == 0 && ver[2] == 6665 && ver[3] < 5003)
    )
    {
      info =
        '\n  Product           : 2007 Office system and the Office Compatibility Pack' +
        '\n  File              : '+ path +
        '\n  Installed version : '+ version +
        '\n  Fixed version     : 12.0.6665.5003' +
        '\n';
      hotfix_add_report(info, bulletin:bulletin, kb:"2687311");
    }
  }
}
if (!version)
{
  # Additional check if registry key is missing
  kb = "2687311";
  if (
    (x86_path && hotfix_is_vulnerable(file:"Excelcnv.exe", version:"12.0.6665.5003", min_version:"12.0.0.0", path:x86_path + "\Microsoft Office\Office12", bulletin:bulletin, kb:kb)) ||
    (x64_path && hotfix_is_vulnerable(file:"Excelcnv.exe", arch:"x64", version:"12.0.6665.5003", min_version:"12.0.0.0", path:x64_path + "\Microsoft Office\Office12", bulletin:bulletin, kb:kb))
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
