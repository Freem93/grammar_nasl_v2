#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49957);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/06/30 19:55:38 $");

  script_cve_id(
    "CVE-2010-3230",
    "CVE-2010-3231",
    "CVE-2010-3232",
    "CVE-2010-3233",
    "CVE-2010-3234",
    "CVE-2010-3235",
    "CVE-2010-3236",
    "CVE-2010-3237",
    "CVE-2010-3238",
    "CVE-2010-3239",
    "CVE-2010-3240",
    "CVE-2010-3241",
    "CVE-2010-3242"
  );
  script_bugtraq_id(43643, 43644, 43646, 43647, 43649, 43650, 43651, 43652, 43653, 43654, 43655, 43656, 43657);
  script_osvdb_id(
    68561,
    68562,
    68563,
    68564,
    68565,
    68566,
    68567,
    68568,
    68569,
    68570,
    68571,
    68572,
    68573
  );
  script_xref(name:"MSFT", value:"MS10-080");

  script_name(english:"MS10-080: Vulnerabilities in Microsoft Excel Could Allow Remote Code Execution (2293211)");
  script_summary(english:"Checks version of Excel");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Arbitrary code can be executed on the remote host through Microsoft
Office Excel."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host is running a version of Microsoft Excel or
Excel Viewer that is affected by several vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Excel file, they could leverage this issue to execute
arbitrary code subject to the user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-080");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Office XP, 2003, 2007,
and Excel Viewer."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/13");

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

bulletin = 'MS10-080';
kbs = make_list("2344875", "2344893", "2345017", "2345035", "2345088");
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

    # Excel 2007.
    office_sp = get_kb_item("SMB/Office/2007/SP");
    if (
      (!isnull(office_sp) && office_sp == 2) &&
      (
        (ver[0] == 12 && ver[1] == 0 && ver[2] < 6545) ||
        (ver[0] == 12 && ver[1] == 0 && ver[2] == 6545 && ver[3] < 5000)
      )
    )
    {
      vuln++;
      info =
        '\n  Product           : Excel 2007' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 12.0.6545.5000\n';
      hotfix_add_report(info, bulletin:bulletin, kb:"2345035");
    }
    # Excel 2003.
    office_sp = get_kb_item("SMB/Office/2003/SP");
    if (
      (!isnull(office_sp) && office_sp == 3) &&
      (ver[0] == 11 && ver[1] == 0 && ver[2] < 8328)
    )
    {
      vuln++;
      info =
        '\n  Product           : Excel 2003' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 11.0.8328.0\n';
      hotfix_add_report(info, bulletin:bulletin, kb:"2344893");
    }
    # Excel 2002.
    office_sp = get_kb_item("SMB/Office/XP/SP");
    if (
      (!isnull(office_sp) && office_sp == 3) &&
      (ver[0] == 10 && ver[1] == 0 && ver[2] < 6866)
    )
    {
      vuln++;
      info =
        '\n  Product           : Excel 2002' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 10.0.6866.0\n';
      hotfix_add_report(info, bulletin:bulletin, kb:"2345017");
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
        ver[2] < 6545 ||
        (ver[2] == 6545 && ver[3] < 5000)
     )
    )
    {
      vuln++;
      info =
        '\n  Product           : Excel Viewer' +
        '\n  File              : '+ path +
        '\n  Installed version : '+ version +
        '\n  Fixed version     : 12.0.6545.5000\n';
      hotfix_add_report(info, bulletin:bulletin, kb:"2345088");
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
        ver[2] < 6545 ||
        (ver[2] == 6545 && ver[3] < 5000)
      )
    )
    {
      vuln++;
      info =
        '\n  Product           : 2007 Office system and the Office Compatibility Pack' +
        '\n  File              : '+ path +
        '\n  Installed version : '+ version +
        '\n  Fixed version     : 12.0.6545.5000\n';
      hotfix_add_report(info, bulletin:bulletin, kb:"2344875");
      break;
    }
  }
}

if (vuln)
{
  set_kb_item(name:"SMB/Missing/MS10-080", value:TRUE);
  hotfix_security_hole();
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
