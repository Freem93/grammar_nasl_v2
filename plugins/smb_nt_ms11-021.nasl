#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53378);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id(
    "CVE-2011-0097",
    "CVE-2011-0098",
    "CVE-2011-0101",
    "CVE-2011-0103",
    "CVE-2011-0104",
    "CVE-2011-0105",
    "CVE-2011-0978",
    "CVE-2011-0979",
    "CVE-2011-0980"
  );
  script_bugtraq_id(46225, 46226, 46229, 47201, 47235, 47243, 47244, 47245, 47256);
  script_osvdb_id(
    70811,
    70812,
    70904,
    71758,
    71759,
    71760,
    71761,
    71765,
    71766
  );
  script_xref(name:"EDB-ID", value:"18067");
  script_xref(name:"EDB-ID", value:"18087");
  script_xref(name:"MSFT", value:"MS11-021");

  script_name(english:"MS11-021: Vulnerabilities in Microsoft Excel Could Allow Remote Code Execution (2489279)");
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
specially crafted Excel file, they could leverage this issue to
execute arbitrary code subject to the user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS11-021");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Office XP, 2003, 2007,
2010, Excel Viewer, and Office Compatability Pack."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS11-021 Microsoft Office 2007 Excel .xlb Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
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

bulletin = 'MS11-021';
kbs = make_list("2464583", "2466146", "2466156", "2466158", "2466169", "2502786");
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

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    # Excel 2010.
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (
      (!isnull(office_sp) && office_sp == 0) &&
      (
        (ver[0] == 14 && ver[1] == 0 && ver[2] < 5130) ||
        (ver[0] == 14 && ver[1] == 0 && ver[2] == 5130 && ver[3] < 5003)
      )
    )
    {
      vuln++;
      info =
        '\n  Product           : Excel 2010' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 14.0.5130.5003\n';
      hotfix_add_report(info, bulletin:bulletin, kb:'2466146');
    }
    # Excel 2007.
    office_sp = get_kb_item("SMB/Office/2007/SP");
    if (
      (!isnull(office_sp) && office_sp == 2) &&
      (
        (ver[0] == 12 && ver[1] == 0 && ver[2] < 6550) ||
        (ver[0] == 12 && ver[1] == 0 && ver[2] == 6550 && ver[3] < 5004)
      )
    )
    {
      vuln++;
      info =
        '\n  Product           : Excel 2007' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 12.0.6550.5004\n';
      hotfix_add_report(info, bulletin:bulletin, kb:"2464583");
    }
    # Excel 2003.
    office_sp = get_kb_item("SMB/Office/2003/SP");
    if (
      (!isnull(office_sp) && office_sp == 3) &&
      (ver[0] == 11 && ver[1] == 0 && ver[2] < 8332)
    )
    {
      vuln++;
      info =
        '\n  Product           : Excel 2003' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 11.0.8332.0\n';
      hotfix_add_report(info, bulletin:bulletin, kb:"2502786");
    }
    # Excel 2002.
    if (
      (!isnull(office_sp) && office_sp == 3) &&
      (ver[0] == 10 && ver[1] == 0 && ver[2] < 6869)
    )
    {
      vuln++;
      info =
        '\n  Product           : Excel 2002' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 10.0.6869.0\n';

      hotfix_add_report(info, bulletin:bulletin, kb:"2466169");
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
    path = 'n/a';

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    # Excel Viewer.
    if (
      ver[0] == 12 && ver[1] == 0 &&
      (
        ver[2] < 6550 ||
        (ver[2] == 6550 && ver[3] < 5004)
      )
    )
    {
      vuln++;
      info =
        '\n  Product           : Excel Viewer' +
        '\n  File              : '+ path +
        '\n  Installed version : '+ version +
        '\n  Fixed version     : 12.0.6550.5004\n';
      hotfix_add_report(info, bulletin:bulletin, kb:"2466158");
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
    version = install - 'SMB/Office/ExcelCnv/' - '/ProductPath';
    path = installs[install];

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    # 2007 Office system and the Office Compatibility Pack.
    if (
      ver[0] == 12 && ver[1] == 0 &&
      (
        ver[2] < 6550 ||
        (ver[2] == 6550 && ver[3] < 5004)
      )
    )
    {
      vuln++;
      info =
        '\n  Product           : 2007 Office system and the Office Compatibility Pack' +
        '\n  File              : '+ path +
        '\n  Installed version : '+ version +
        '\n  Fixed version     : 12.0.6550.5004\n';
      hotfix_add_report(info, bulletin:bulletin, kb:"2466156");
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
