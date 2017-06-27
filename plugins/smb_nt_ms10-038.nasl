#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46845);
  script_version("$Revision: 1.34 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id(
    "CVE-2010-0821",
    "CVE-2010-0822",
    "CVE-2010-0823",
    "CVE-2010-0824",
    "CVE-2010-1245",
    "CVE-2010-1246",
    "CVE-2010-1247",
    "CVE-2010-1248",
    "CVE-2010-1249",
    "CVE-2010-1250",
    "CVE-2010-1251",
    "CVE-2010-1252",
    "CVE-2010-1253"
    # "CVE-2010-1254"    # nb: affects only Mac Office Open XML
  );
  script_bugtraq_id(
    40518,
    40520,
    40521,
    40522,
    40523,
    40524,
    40525,
    40526,
    40527,
    40528,
    40529,
    40530,
    40531
  );
  script_osvdb_id(
    65226,
    65227,
    65228,
    65229,
    65230,
    65231,
    65232,
    65233,
    65235,
    65236,
    65237,
    65238,
    65239
  );
  script_xref(name:"EDB-ID", value:"18143");
  script_xref(name:"MSFT", value:"MS10-038");

  script_name(english:"MS10-038: Vulnerabilities in Microsoft Office Excel Could Allow Remote Code Execution (2027452)");
  script_summary(english:"Checks version of Excel et al.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Arbitrary code can be executed on the remote host through Microsoft
Office Excel."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host contains a version of Microsoft Office Excel 2002,
Microsoft Office Excel 2003, Microsoft Office Excel 2007, Microsoft
Office Excel Viewer, or Microsoft Office Compatibility Pack that is
affected by several vulnerabilities.

If an attacker can trick a user on the affected system into opening a
specially crafted Excel file using the affected application, he may be
able to leverage these issues to execute arbitrary code subject to the
user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-038");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Office Excel 2002,
Office Excel 2003, Excel 2007, Office Excel Viewer and Office
Compatibility Pack."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS11-038 Microsoft Office Excel Malformed OBJ Record Handling Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS10-038';
kbs = make_list("982133", "982299", "982308", "982331", "982333");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


info = "";

vuln = 0;
kb = '';
# Excel.
installs = get_kb_list("SMB/Office/Excel/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install -'SMB/Office/Excel/' - '/ProductPath';
    path = installs[install];
    if (isnull(path)) path = 'n/a';

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    # Excel 2007.
    office_sp = get_kb_item("SMB/Office/2007/SP");
    if (
      (!isnull(office_sp) && (office_sp == 1 || office_sp == 2)) &&
      (
        ver[0] == 12 && ver[1] == 0 &&
        (
          ver[2] < 6535 ||
          (ver[2] == 6535 && ver[3] < 5002)
        )
      )
    )
    {
      vuln++;
      info =
        '\n  Product           : Excel 2007' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 12.0.6535.5002\n';
      kb = '982308';
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
    }
    # Excel 2003.
    else if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8324)
    {
      office_sp = get_kb_item("SMB/Office/2003/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        vuln++;
        info =
          '\n  Product           : Excel 2003' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 11.0.8324.0\n';
        kb = '982133';
        hotfix_add_report(info, bulletin:bulletin, kb:kb);
      }
    }
    # Excel 2002.
    else if (ver[0] == 10 && ver[1] == 0 && ver[2] < 6862)
    {
      office_sp = get_kb_item("SMB/Office/XP/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        vuln++;
        info =
          '\n  Product           : Excel 2002' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 10.0.6862.0\n';
        kb = '982299';
        hotfix_add_report(info, bulletin:bulletin, kb:kb);
      }
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

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    # Excel Viewer.
    if (
      ver[0] == 12 && ver[1] == 0 &&
      (
        ver[2] < 6535 ||
        (ver[2] == 6535 && ver[3] < 5000)
      )
    )
    {
      vuln++;
      info =
        '\n  Product           : Excel Viewer' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 12.0.6535.5000\n';
      kb = '982333';
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
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
        ver[2] < 6535 ||
        (ver[2] == 6535 && ver[3] < 5000)
      )
    )
    {
      vuln++;
      info =
        '\n  Product           : 2007 Office system and the Office Compatibility Pack' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 12.0.6535.5000\n';
      kb = '982331';
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
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
