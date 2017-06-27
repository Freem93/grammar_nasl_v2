#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55125);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id(
    "CVE-2011-1272",
    "CVE-2011-1273",
    "CVE-2011-1274",
    "CVE-2011-1275",
    "CVE-2011-1276",
    "CVE-2011-1277",
    "CVE-2011-1278",
    "CVE-2011-1279"
  );
  script_bugtraq_id(48157, 48158, 48159, 48160, 48161, 48162, 48163, 48164);
  script_osvdb_id(72920, 72921, 72922, 72923, 72924, 72925, 72926, 72927);
  script_xref(name:"EDB-ID", value:"17643");
  script_xref(name:"IAVA", value:"2011-A-0086");
  script_xref(name:"MSFT", value:"MS11-045");

  script_name(english:"MS11-045: Vulnerabilities in Microsoft Excel Could Allow Remote Code Execution (2537146)");
  script_summary(english:"Checks version of Excel");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Arbitrary code can be executed on the remote host through Microsoft
Excel."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host is running a version of Microsoft Excel or
Excel Viewer that is affected by several vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Excel file, he or she could leverage this issue to
execute arbitrary code subject to the user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-045");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Office XP, 2003, 2007,
2010, Excel Viewer, and Office Compatability Pack."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS11-045';
kbs = make_list("2523021", "2541003", "2541007", "2541012", "2541015", "2541025");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

info = "";


# Excel.
vuln = 0;
installs = get_kb_list("SMB/Office/Excel/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/Excel/' - '/ProductPath';
    path = installs[install];
    if (isnull(path)) path = "n/a";

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    # Excel 2010.
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (
      (!isnull(office_sp) && (office_sp == 0)) &&
      (
        (ver[0] == 14 && ver[1] == 0 && ver[2] < 5138) ||
        (ver[0] == 14 && ver[1] == 0 && ver[2] == 5138 && ver[3] < 5000)
      )
    )
    {
      vuln++;
      info =
        '\n  Product           : Excel 2010' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 14.0.5138.5000\n';
      hotfix_add_report(info, bulletin:bulletin, kb:'2523021');
     }
    # Excel 2007.
    office_sp = get_kb_item("SMB/Office/2007/SP");
    if (
      (!isnull(office_sp) && office_sp == 2) &&
      (
        (ver[0] == 12 && ver[1] == 0 && ver[2] < 6557) ||
        (ver[0] == 12 && ver[1] == 0 && ver[2] == 6557 && ver[3] < 5000)
      )
    )
    {
      vuln++;
      info =
        '\n  Product           : Excel 2007' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 12.0.6557.5000\n';
      hotfix_add_report(info, bulletin:bulletin, kb:"2541007");
    }
    # Excel 2003.
    office_sp = get_kb_item("SMB/Office/2003/SP");
    if (
      (!isnull(office_sp) && office_sp == 3) &&
      (ver[0] == 11 && ver[1] == 0 && ver[2] < 8335)
    )
    {
      vuln++;
      info =
        '\n  Product           : Excel 2003' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 11.0.8335.0\n';
      hotfix_add_report(info, bulletin:bulletin, kb:"2541025");
    }
    # Excel 2002.
    office_sp = get_kb_item("SMB/Office/XP/SP");
    if (
      (!isnull(office_sp) && office_sp == 3) &&
      (ver[0] == 10 && ver[1] == 0 && ver[2] < 6871)
    )
    {
      vuln++;
      info =
        '\n  Product           : Excel 2002' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 10.0.6871.0\n';

      hotfix_add_report(info, bulletin:bulletin, kb:"2541003");
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
    if (isnull(path)) path = "n/a";

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    # Excel Viewer.
    if (
      ver[0] == 12 && ver[1] == 0 &&
      (
        ver[2] < 6557 ||
        (ver[2] == 6557 && ver[3] < 5000)
      )
    )
    {
      vuln++;
      info =
        '\n  Product           : Excel Viewer' +
        '\n  File              : '+ path +
        '\n  Installed version : '+ version +
        '\n  Fixed version     : 12.0.6557.5000\n';
      hotfix_add_report(info, bulletin:bulletin, kb:"2541015");
      break;
    }
  }
}


# 2007 Microsoft Office system and the Microsoft Office Compatibility Pack.
installs = get_kb_list("SMB/Office/ExcelCnv/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - '/SMB/Office/ExcelCnv/' - '/ProductPath';
    path = installs[install];
    if (isnull(path)) path = "n/a";

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    # 2007 Office system and the Office Compatibility Pack.
    if (
      ver[0] == 12 && ver[1] == 0 &&
      (
        ver[2] < 6557 ||
        (ver[2] == 6557 && ver[3] < 5000)
      )
    )
    {
      vuln++;
      info =
        '\n  Product           : 2007 Office system and the Office Compatibility Pack' +
        '\n  File              : '+ path +
        '\n  Installed version : '+ version +
        '\n  Fixed version     : 12.0.6557.5000\n';
      hotfix_add_report(info, bulletin:bulletin, kb:"2541012");
      break;
    }
  }
}

if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
