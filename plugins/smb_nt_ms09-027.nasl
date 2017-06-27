#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39349);
  script_version("$Revision: 1.31 $");
  script_cvs_date("$Date: 2016/12/09 20:55:00 $");

  script_cve_id("CVE-2009-0563", "CVE-2009-0565");
  script_bugtraq_id(35188, 35190);
  script_osvdb_id(54959, 54960);
  script_xref(name:"MSFT", value:"MS09-027");

  script_name(english:"MS09-027: Vulnerabilities in Microsoft Office Word Could Allow Remote Code Execution (969514)");
  script_summary(english:"Checks version of Word");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Word.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of Microsoft Word or
Word Viewer that is affected by two buffer overflow vulnerabilities.
If an attacker can trick a user on the affected host into opening a
specially crafted Word file, he could leverage these issues to execute
arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-027");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-09-035/");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Word 2000, 2002, 2003 and
Word 2007, Word Viewer and Word Viewer 2003 as well as the 2007
Microsoft Office system and the Microsoft Office Compatibility Pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
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


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("audit.inc");


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS09-027';
kbs = make_list("969600", "969602", "969603", "969604", "969613", "969614");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


if (!get_kb_item("SMB/WindowsVersion")) exit(0, "The 'SMB/WindowsVersion' KB item is missing.");


info = "";
vuln = 0;

# Word.
installs = get_kb_list("SMB/Office/Word/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/Word/' - '/ProductPath';
    path = installs[install];

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    # Word 2007.
    if (
      ver[0] == 12 && ver[1] == 0 &&
      (
        ver[2] < 6504 ||
        (ver[2] == 6504 && ver[3] < 5000)
      )
    )
    {
      office_sp = get_kb_item("SMB/Office/2007/SP");
      if (!isnull(office_sp) && (office_sp == 1 || office_sp == 2))
      {
        vuln++;
        kb = "969604";

        info =
          '\n  Product           : Word 2007' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 12.0.6504.5000\n';
        hotfix_add_report(info, bulletin:bulletin, kb:kb);
      }
    }
    # Word 2003.
    else if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8307)
    {
      office_sp = get_kb_item("SMB/Office/2003/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        vuln++;
        kb = "969603";

        info =
          '\n  Product           : Word 2003' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 11.0.8307.0\n';
        hotfix_add_report(info, bulletin:bulletin, kb:kb);
      }
    }
    # Word 2002.
    else if (ver[0] == 10 && ver[1] == 0 && ver[2] < 6854)
    {
      office_sp = get_kb_item("SMB/Office/XP/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        vuln++;
        kb = "969602";

        info =
          '\n  Product           : Word 2002' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 10.0.6854.0\n';
        hotfix_add_report(info, bulletin:bulletin, kb:kb);
      }
    }
    # Word 2000.
    else if (ver[0] == 9 && ver[1] == 0 && ver[2] == 0 && ver[3] < 8979)
    {
      office_sp = get_kb_item("SMB/Office/2000/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        vuln++;
        kb = "969600";

        info =
          '\n  Product           : Word 2000' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 9.0.0.8979\n';
        hotfix_add_report(info, bulletin:bulletin, kb:kb);
      }
    }
  }
}


# Word Viewer.
installs = get_kb_list("SMB/Office/WordViewer/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/WordViewer/' - '/ProductPath';
    path = installs[install];

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
      ver[i] = int(ver[i]);

    # Word Viewer 2003.
    if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8307)
    {
      vuln++;
      kb = "969614";

      info =
        '\n  Product           : Word Viewer / Word Viewer 2003' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 11.0.8307.0\n';
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
    }
  }
}

# 2007 Microsoft Office system and the Microsoft Office Compatibility Pack.
share = '';
lastshare = '';
accessibleshare = FALSE;
installs = get_kb_list("SMB/Office/WordCnv/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/WordCnv/' - '/ProductPath';
    path = installs[install];

    share = hotfix_path2share(path:path);
    if (share != lastshare || !accessibleshare)
    {
      lastshare = share;
      if (is_accessible_share(share:share))
      {
        accessibleshare = TRUE;
      }
      else accessibleshare = FALSE;
    }
    if (accessibleshare)
    {
      path = path - '\\Wordconv.exe';
      file = "wordcnv.dll";

      if (hotfix_check_fversion(path:path, file:file, version:"12.0.6504.5000") == HCF_OLDER)
      {
        vuln++;
        file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\" + file);
        kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
        version = get_kb_item(kb_name);

        info =
          '\n  Product           : Microsoft Office Compatibility Pack for Word, Excel, and PowerPoint 2007 File Formats' +
          '\n  File              : ' + path + '\\' + file +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 12.0.6504.5000' + '\n';

        hotfix_add_report(info, bulletin:bulletin, kb:"969613");
      }
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
