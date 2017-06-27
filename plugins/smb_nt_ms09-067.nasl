#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42441);
  script_version("$Revision: 1.28 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id(
    "CVE-2009-3127",
    "CVE-2009-3128",
    "CVE-2009-3129",
    "CVE-2009-3130",
    "CVE-2009-3131",
    "CVE-2009-3132",
    "CVE-2009-3133",
    "CVE-2009-3134"
  );
  script_bugtraq_id(36908, 36909, 36911, 36912, 36943, 36944, 36945, 36946);
  script_osvdb_id(59858, 59859, 59860, 59861, 59862, 59863, 59864, 59866);
  script_xref(name:"MSFT", value:"MS09-067");
  script_xref(name:"EDB-ID", value:"14706");
  script_xref(name:"EDB-ID", value:"16625");

  script_name(english:"MS09-067: Vulnerabilities in Microsoft Office Excel Could Allow Remote Code Execution (972652)");
  script_summary(english:"Checks the version of all affected Excel renderers");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Arbitrary code can be executed on the remote host through opening a
Microsoft Excel file."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host contains a version of Microsoft Excel, Excel Viewer,
2007 Microsoft Office system, or Microsoft Office Compatibility Pack
that is affected by several memory corruption vulnerabilities.  An
attacker could exploit this by tricking a user into opening a
maliciously crafted Excel file, resulting in the execution of
arbitrary code subject to the user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-067");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-09-083/");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Office XP, Office 2003,
Office 2007, and Office Excel Viewer."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS09-067 Microsoft Excel Malformed FEATHEADER Record Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(94, 119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
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

bulletin = 'MS09-067';
kbs = make_list("973471", "973475", "973484", "973593", "973704", "973707");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


info = "";

# Excel.

kb = '';
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
    if (
      ver[0] == 12 && ver[1] == 0 &&
      (
        ver[2] < 6514 ||
        (ver[2] == 6514 && ver[3] < 5000)
      )
    )
    {
      office_sp = get_kb_item("SMB/Office/2007/SP");
      if (!isnull(office_sp) && (office_sp == 1 || office_sp == 2))
      {
        vuln++;
        info =
          '\n  Product           : Excel 2007' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 12.0.6514.5000\n';
        kb = '973593';
        hotfix_add_report(info, bulletin:bulletin, kb:kb);
      }
    }
    # Excel 2003.
    else if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8316)
    {
      office_sp = get_kb_item("SMB/Office/2003/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        vuln++;
        info =
          '\n  Product           : Excel 2003' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 11.0.8316.0\n';
        kb = '973475';
        hotfix_add_report(info, bulletin:bulletin, kb:kb);
      }
    }
    # Excel 2002.
    else if (ver[0] == 10 && ver[1] == 0 && ver[2] < 6856)
    {
      office_sp = get_kb_item("SMB/Office/XP/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        vuln++;
        info =
          '\n  Product           : Excel 2002' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 10.0.6856.0\n';
        kb = '973471';
        hotfix_add_report(info, bulletin:bulletin, kb:kb);
      }
    }
  }
}


# Excel Viewer.
installs = get_kb_item("SMB/Office/ExcelViewer/*/ProductPath");
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
        ver[2] < 6514 ||
        (ver[2] == 6514 && ver[3] < 5000)
      )
    )
    {
      vuln++;
      info =
        '\n  Product           : Excel Viewer' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 12.0.6514.5000\n';
      kb = '973707';
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
    }
    # Excel Viewer 2003.
    else if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8313)
    {
      vuln++;
      info =
        '\n  Product           : Excel 2003' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 11.0.8313.0\n';
      kb = '973484';
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

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    # 2007 Office system and the Office Compatibility Pack.
    if (
      ver[0] == 12 && ver[1] == 0 &&
      (
        ver[2] < 6514 ||
        (ver[2] == 6514 && ver[3] < 5000)
      )
    )
    {
      info =
        '\n  Product           : 2007 Office system and the Office Compatibility Pack' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 12.0.6514.5000\n';
      kb = '973704';
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
