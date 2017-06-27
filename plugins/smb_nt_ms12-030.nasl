#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59038);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/03 21:08:35 $");

  script_cve_id(
    "CVE-2012-0184",
    "CVE-2012-0185",
    "CVE-2012-0141",
    "CVE-2012-0142",
    "CVE-2012-0143",
    "CVE-2012-1847"
  );
  script_bugtraq_id(
    53342,
    53373,
    53374,
    53375,
    53376,
    53379
  );
  script_osvdb_id(81723, 81724, 81725, 81726, 81727, 81728);
  script_xref(name:"MSFT", value:"MS12-030");

  script_name(english:"MS12-030: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (2663830)");
  script_summary(english:"Checks versions of Excel and xl12cnv.exe.");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Office.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of Microsoft Office,
Excel, or a related product that is affected by several
vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Excel file, they could leverage these issues to
execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-157/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Aug/279");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-030");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Excel 2003, 2007, 2010,
Office 2007, 2010, Excel Viewer, and Office Compatibility Pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
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

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");
include("audit.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS12-030";
kbs = make_list(
  "2553371", "2596842", "2597086", "2597161",
  "2597162", "2597166", "2597969"
);

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

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
      (!isnull(office_sp) && (office_sp == 0 || office_sp == 1)) &&
      (
        (ver[0] == 14 && ver[1] == 0 && ver[2] < 6117) ||
        (ver[0] == 14 && ver[1] == 0 && ver[2] == 6117 && ver[3] < 5003)
      )
    )
    {
      vuln = TRUE;
      info =
        '\n  Product           : Excel 2010' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 14.0.6117.5003' +
        '\n';
      hotfix_add_report(info, bulletin:bulletin, kb:"2597166");
    }

    # Excel 2007.
    office_sp = get_kb_item("SMB/Office/2007/SP");
    if (
      (!isnull(office_sp) && (office_sp == 2 || office_sp == 3)) &&
      (
        (ver[0] == 12 && ver[1] == 0 && ver[2] < 6661) ||
        (ver[0] == 12 && ver[1] == 0 && ver[2] == 6661 && ver[3] < 5000)
      )
    )
    {
      vuln = TRUE;
      info =
        '\n  Product           : Excel 2007' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 12.0.6661.5000' +
        '\n';
      hotfix_add_report(info, bulletin:bulletin, kb:"2597161");
    }

    # Excel 2003.
    office_sp = get_kb_item("SMB/Office/2003/SP");
    if ((!isnull(office_sp) && office_sp == 3) && (ver[0] == 11 && ver[1] == 0 && ver[2] < 8346))
    {
      vuln = TRUE;
      info =
        '\n  Product           : Excel 2003' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 11.0.8346.0' +
        '\n';
      hotfix_add_report(info, bulletin:bulletin, kb:"2597086");
    }
  }
}

######################################################################
# Excel Viewer
######################################################################
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
      (ver[0] == 12 && ver[1] == 0 && ver[2] >= 6424) &&
      (
        (ver[0] == 12 && ver[1] == 0 && ver[2] < 6658) ||
        (ver[0] == 12 && ver[1] == 0 && ver[2] == 6658 && ver[3] < 5004)
      )
    )
    {
      vuln = TRUE;
      info =
        '\n  Product           : Excel Viewer' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 12.0.6658.5004' +
        '\n';
      hotfix_add_report(info, bulletin:bulletin, kb:"2596842");
      break;
    }
  }
}

######################################################################
# Microsoft Office Compatibility Pack
######################################################################
installs = get_kb_list("SMB/Office/ExcelCnv/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/ExcelCnv/' - '/ProductPath';
    path = installs[path];
    if (isnull(path)) path = "n/a";

    ver = split(version, sep:".", keep:FALSE);
    for (i = 0; i < max_index(ver); i++)
      ver[i] = int(ver[i]);

    if (
      (ver[0] == 12 && ver[1] == 0 && ver[2] < 6661) ||
      (ver[0] == 12 && ver[1] == 0 && ver[2] == 6661 && ver[3] < 5000)
    )
    {
      vuln = TRUE;
      info =
        '\n  Product           : 2007 Office system and the Office Compatibility Pack' +
        '\n  File              : '+ path +
        '\n  Installed version : '+ version +
        '\n  Fixed version     : 12.0.6661.5000' +
        '\n';
      hotfix_add_report(info, bulletin:bulletin, kb:"2597162");
      break;
    }
  }
}

######################################################################
# Office
######################################################################
office_vers = hotfix_check_office_version();
x86_path = hotfix_get_commonfilesdir();
x64_path = hotfix_get_programfilesdirx86();

# Office 2010 SP0 and SP1.
if (office_vers["14.0"])
{
  office_sp = get_kb_item("SMB/Office/2010/SP");
  if (!isnull(office_sp) && office_sp <= 1)
  {
    kb = "2553371";
    if (
      (x86_path && hotfix_is_vulnerable(file:"Graph.exe", version:"14.0.6117.5003", min_version:"14.0.0.0", path:x86_path + "\Microsoft Shared\Office14", bulletin:bulletin, kb:kb)) ||
      (x64_path && hotfix_is_vulnerable(file:"Graph.exe", arch:"x64", version:"14.0.6117.5003", min_version:"14.0.0.0", path:x64_path + "\Common Files\Microsoft Shared\Office14", bulletin:bulletin, kb:kb))
    ) vuln = TRUE;
  }
}
# Office 2007 SP2 and SP3.
if (office_vers["12.0"])
{
  office_sp = get_kb_item("SMB/Office/2007/SP");
  if (!isnull(office_sp) && (office_sp == 2 || office_sp == 3))
  {
    kb = "2597969";
    if (
      (x86_path && hotfix_is_vulnerable(file:"Graph.exe", version:"12.0.6658.5004", min_version:"12.0.0.0", path:x86_path + "\Microsoft Shared\Office12", bulletin:bulletin, kb:kb)) ||
      (x64_path && hotfix_is_vulnerable(file:"Graph.exe", arch:"x64", version:"12.0.6658.5004", min_version:"12.0.0.0", path:x64_path + "\Common Files\Microsoft Shared\Office12", bulletin:bulletin, kb:kb))
    ) vuln = TRUE;
  }
}
hotfix_check_fversion_end();
if (vuln)
{
  set_kb_item(name:"SMB/Missing/" + bulletin, value:TRUE);
  hotfix_security_hole();
}
else audit(AUDIT_HOST_NOT, 'affected');
