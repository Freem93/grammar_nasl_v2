#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36147);
  script_version("$Revision: 1.30 $");
  script_cvs_date("$Date: 2016/12/09 20:55:00 $");

  script_cve_id("CVE-2009-0100", "CVE-2009-0238");
  script_bugtraq_id(33870, 34413);
  script_osvdb_id(52695, 53665);
  script_xref(name:"MSFT", value:"MS09-009");

  script_name(english:"MS09-009: Vulnerabilities in Microsoft Office Excel Could Cause Remote Code Execution (968557)");
  script_summary(english:"Checks version of Excel.exe / Xlview.exe / Excelcnv.exe");

  script_set_attribute(
    attribute:"synopsis",
    value:
"It is possible to execute arbitrary code on the remote Windows host
using Microsoft Excel."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host contains a version of Microsoft Excel / Excel Viewer
/ 2007 Microsoft Office system and the Microsoft Office Compatibility
Pack that is affected by two memory corruption vulnerabilities.  If an
attacker can trick a user on the affected host into opening a
specially crafted Excel file, either of these issues could be
leveraged to run arbitrary code on the host subject to the user's
privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-009");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Excel 2000, 2002, 2003,
and 2007, Excel Viewer and Excel Viewer 2003 as well as the 2007
Microsoft Office system and the Microsoft Office Compatibility Pack."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(94, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nt_ms02-031.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}


include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");
include("audit.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS09-009';
kbs = make_list("959964", "959988", "959993", "959995", "959997", "960000", "960003");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

# Excel
info = "";
kb = "";
vuln = 0;
installs = get_kb_list("SMB/Office/Excel/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/Excel/' - '/ProductPath';
    path = installs[install];
    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    if (isnull(path)) path = "n/a";
    if (
      # Excel 2007 - fixed in 12.0.6341.5001
      ver[0] == 12 && ver[1] == 0 &&
      (
        ver[2] < 6341 ||
        (ver[2] == 6341 && ver[3] < 5001)
      )
    )
    {
      office_sp = get_kb_item("SMB/Office/2007/SP");
      if (!isnull(office_sp) && office_sp == 1)
      {
        vuln++;
        kb = "959997";
        info =
          '\n  Product           : Excel 2007' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 10.0.6341.5001\n';
        hotfix_add_report(info, bulletin:bulletin, kb:kb);
      }
    }

    # Excel 2003 - fixed in 11.0.8302.0
    else if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8302)
    {
      office_sp = get_kb_item("SMB/Office/2003/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        vuln++;
        kb = "959995";
        info =
          '\n  Product           : Excel 2003' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 11.0.8302.0\n';
        hotfix_add_report(info, bulletin:bulletin, kb:kb);
      }
    }

    # Excel 2002 - fixed in 10.0.6852.0
    else if (ver[0] == 10 && ver[1] == 0 && ver[2] < 6852)
    {
      office_sp = get_kb_item("SMB/Office/XP/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        vuln++;
        kb = "959988";
        info =
          '\n  Product           : Excel 2002' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 10.0.6852.0\n';
        hotfix_add_report(info, bulletin:bulletin, kb:kb);
      }
    }

    # Excel 2000 - fixed in 9.0.0.8977
    else if (ver[0] == 9 && ver[1] == 0 && ver[2] == 0 && ver[3] < 8977)
    {
      office_sp = get_kb_item("SMB/Office/2000/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        vuln++;
        kb = "959964";
        info =
          '\n  Product           : Excel 2000' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 9.0.0.8977\n';
        hotfix_add_report(info, bulletin:bulletin, kb:kb);
      }
    }
  }
}

# Excel Viewer
installs = get_kb_list("SMB/Office/ExcelViewer/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/ExcelViewer/' - '/ProductPath';
    path = installs[install];

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    if (
      # Excel - fixed in 12.0.6341.5001
      ver[0] == 12 && ver[1] == 0 &&
      (
        ver[2] < 6341 ||
        (ver[2] == 6341 && ver[3] < 5001)
      )
    )
    {
      vuln++;
      kb = "960000";
      info =
        '\n  Product           : Excel Viewer' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 12.0.6341.5001\n';
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
    }

    # Excel Viewer 2003 - fixed in 11.0.8302.0
    else if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8302)
    {
      vuln++;
      kb = "959993";
      info =
        '\n  Product           : Excel Viewer 2003' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 11.0.8302.0\n';
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
    }
  }
}


# 2007 Microsoft Office system and the Microsoft Office Compatibility Pack
installs = get_kb_list("SMB/Office/ExcelCnv/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/ExcelCnv/' - '/ProductPath';
    path = installs[install];

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    if (
      # fixed in 12.0.6341.5001
      ver[0] == 12 && ver[1] == 0 &&
      (
        ver[2] < 6341 ||
        (ver[2] == 6341 && ver[3] < 5001)
      )
    )
    {
      vuln++;
      kb = "960003";
      info =
        '\n  Product           : Excel 2007 Converter' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 12.0.6341.5001\n';
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
    }
  }
}
if (vuln)
{
  set_kb_item(name:"SMB/Missing/MS09-009", value:TRUE);
  hotfix_security_hole();
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
