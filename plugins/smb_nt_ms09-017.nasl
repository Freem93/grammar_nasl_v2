#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38742);
  script_version("$Revision: 1.36 $");
  script_cvs_date("$Date: 2016/12/09 20:55:00 $");

  script_cve_id(
    "CVE-2009-0220",
    "CVE-2009-0221",
    "CVE-2009-0222",
    "CVE-2009-0223",
    "CVE-2009-0224",
    "CVE-2009-0225",
    "CVE-2009-0226",
    "CVE-2009-0227",
    "CVE-2009-0556",
    "CVE-2009-1128",
    "CVE-2009-1129",
    "CVE-2009-1130",
    "CVE-2009-1131",
    "CVE-2009-1137"
  );
  script_bugtraq_id(
    34351,
    34831,
    34833,
    34834,
    34835,
    34837,
    34839,
    34840,
    34841,
    34876,
    34879,
    34880,
    34881,
    34882
  );
  script_osvdb_id(
    53182,
    54381,
    54382,
    54383,
    54384,
    54385,
    54386,
    54387,
    54388,
    54389,
    54390,
    54391,
    54392,
    54393,
    54394
  );
  script_xref(name:"CERT", value:"627331");
  script_xref(name:"IAVA", value:"2009-A-0039");
  script_xref(name:"MSFT", value:"MS09-017");

  script_name(english:"MS09-017: Vulnerabilities in Microsoft Office PowerPoint Could Allow Remote Code Execution (967340)");
  script_summary(english:"Checks version of PowerPoint");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Arbitrary code can be executed on the remote host through Microsoft
PowerPoint."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host is running a version of Microsoft PowerPoint,
PowerPoint Viewer, or PowerPoint Converter that is affected by
multiple vulnerabilities.  If an attacker can trick a user on the
affected host into opening a specially crafted PowerPoint file, he
could leverage these issues to execute arbitrary code subject to the
user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-017");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-09-019/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-09-020/");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for PowerPoint 2000, 2002,
2003, and 2007, PowerPoint Viewer 2003 and 2007, as well as the
Microsoft Office Compatibility Pack."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(94, 119, 189);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/04/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

bulletin = 'MS09-017';
kbs = make_list("957781", "957784", "957789", "957790", "969615", "969618", "970059");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


# PowerPoint.
info = "";
pp_patched = FALSE;
vuln = 0;
kb = "";
installs = get_kb_list("SMB/Office/PowerPoint/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/PowerPoint/' - '/ProductPath';
    path = installs[install];
    if (isnull(path)) path = "n/a";

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    # PowerPoint 2007.
    if (
      ver[0] == 12 && ver[1] == 0 &&
      (
        ver[2] < 6500 ||
        (ver[2] == 6500 && ver[3] < 5000)
      )
    )
    {
      office_sp = get_kb_item("SMB/Office/2007/SP");
      if (!isnull(office_sp) && (office_sp == 1 || office_sp == 2))
      {
        vuln++;
        kb = "957789";
        info =
          '\n  Product           : PowerPoint 2007' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 12.0.6500.5000\n';
        hotfix_add_report(info, bulletin:bulletin, kb:kb);
      }
    }
    # PowerPoint 2003.
    else if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8307)
    {
      office_sp = get_kb_item("SMB/Office/2003/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        vuln++;
        kb = "957784";
        info =
          '\n  Product           : PowerPoint 2003' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 11.0.8307.0\n';
        hotfix_add_report(info, bulletin:bulletin, kb:kb);
      }
    }
    # PowerPoint 2002.
    else if (ver[0] == 10 && ver[1] == 0 && ver[2] < 6853)
    {
      office_sp = get_kb_item("SMB/Office/XP/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        vuln++;
        kb = "957781";
        info =
          '\n  Product           : PowerPoint 2002' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 10.0.6853.0\n';
        hotfix_add_report(info, bulletin:bulletin, kb:kb);
      }
    }
    # PowerPoint 2000 - fixed in 9.0.0.8978
    else if (ver[0] == 9 && ver[1] == 0 && ver[2] == 0 && ver[3] < 8978)
    {
      office_sp = get_kb_item("SMB/Office/2000/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        vuln++;
        kb = "957790";
        info =
          '\n  Product           : PowerPoint 2000' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 9.0.0.8978\n';
        hotfix_add_report(info, bulletin:bulletin, kb:kb);
      }
    }
  }
}
if (!vuln) pp_patched = TRUE;

# PowerPoint Viewer.
installs = get_kb_list("SMB/Office/PowerPointViewer/*/ProductPath");
if (!isnull(installs) && !pp_patched)
{
  version = install - 'SMB/Office/PowerPointViewer/' - '/ProductPath';
  path = installs[install];
  if (isnull(path)) path = 'n/a';

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # PowerPoint Viewer 2007.
  if (
    ver[0] == 12 && ver[1] == 0 &&
    (
      ver[2] < 6502 ||
      (ver[2] == 6502 && ver[3] < 5000)
    )
  )
  {
    vuln++;
    kb = "970059";
    info =
      '\n  Product           : PowerPoint Viewer 2007' +
      '\n  File              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 12.0.6502.5000\n';
    hotfix_add_report(info, bulletin:bulletin, kb:kb);
  }
  # Office PowerPoint Viewer 2003.
  else if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8305)
  {
    kb = "969615";
    info =
      '\n  Product           : Office PowerPoint Viewer 2003' +
      '\n  File              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 11.0.8305.0\n';
    hotfix_add_report(info, bulletin:bulletin, kb:kb);
  }
}

# PowerPoint Converter.
installs = get_kb_list("SMB/Office/PowerPointCnv/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/PowerPointCnv/' - '/ProductPath';
    path = installs[install];
    if (isnull(path)) path = 'n/a';

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    #  PowerPoint 2007 converter.
    if (
      ver[0] == 12 && ver[1] == 0 &&
      (
        ver[2] < 6500 ||
        (ver[2] == 6500 && ver[3] < 5000)
      )
    )
    {
      vuln++;
      kb = "969618";
      info =
        '\n  Product           : PowerPoint 2007 Converter' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 12.0.6500.5000\n';
      hotfix_add_report(info, kb:kb, bulletin:bulletin);
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
