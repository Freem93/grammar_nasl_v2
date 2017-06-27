#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48293);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/07/11 14:12:52 $");

  script_cve_id("CVE-2010-1900", "CVE-2010-1901", "CVE-2010-1902", "CVE-2010-1903");
  script_bugtraq_id(42130, 42132, 42133, 42136);
  script_osvdb_id(66994, 66995, 66996, 66997);
  script_xref(name:"MSFT", value:"MS10-056");

  script_name(english:"MS10-056: Vulnerability in Microsoft Office Word Could Allow Remote Code Execution (2269638)");
  script_summary(english:"Checks version of Word");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Arbitrary code can be executed on the remote host through Microsoft
Word."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host is running a version of Microsoft Word or
Word Viewer that is affected by several vulnerabilities.  If an
attacker can trick a user on the affected host into opening a
specially crafted Word file, he could leverage this issue to execute
arbitrary code subject to the user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-056");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Office XP, Word 2003, and
Word Viewer."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:works");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS10-056';
kbs = make_list("2251389", "2251399", "2251419", "2251437", "2277947");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

info = "";

vuln = 0;
kb = "";
# Word.
installs = get_kb_list("SMB/Office/Word/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/Word/' - '/ProductPath';
    path = installs[install];
    if (isnull(path)) path = 'n/a';

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

    # Word 2007.
    office_sp = get_kb_item("SMB/Office/2007/SP");
    if (
      (!isnull(office_sp) && office_sp == 2) &&
      (
        ver[0] == 12 && ver[1] == 0 &&
        (
          ver[2] < 6541 ||
          (ver[2] == 6541 && ver[3] < 5000)
        )
      )
    )
    {
      vuln++;
      info =
        '\n  Product           : Word 2007' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 12.0.6541.5000' + '\n';
      kb = '2251419';
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
    }

    # Word 2003.
    office_sp = get_kb_item("SMB/Office/2003/SP");
    if (
      (!isnull(office_sp) && office_sp == 3) &&
      (ver[0] == 11 && ver[1] == 0 && ver[2] < 8326)
    )
    {
      vuln++;
      info =
        '\n  Product           : Word 2003' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 11.0.8326.0' + '\n';
      kb = '2251399';
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
    }

    # Word 2002.
    office_sp = get_kb_item("SMB/Office/XP/SP");
    if (
      (!isnull(office_sp) && office_sp == 3) &&
      (ver[0] == 10 && ver[1] == 0 && ver[2] < 6864)
    )
    {
      vuln++;
      info =
        '\n  Product           : Word 2002' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 10.0.6864.0' + '\n';
      kb = '2251389';
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
    }
  }
}


# Word Viewer.
installs = get_kb_list("SMB/Office/WordViewer/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = isntall - 'SMB/Office/WordViewer/' - '/ProductPath';
    path = installs[install];

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

    # Word Viewer 2003.
    if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8326)
    {
      vuln++;
      info =
        '\n  Product           : Word Viewer 2003' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 11.0.8326.0' + '\n';
      kb = '2251437';
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
    }
  }
}

# 2007 Microsoft Office system and the Microsoft Office Compatibility Pack.
share = '';
lastshare = '';
accessibleshare = FALSE;
installs = get_kb_list("SMB/Ofice/WordCnv/*/ProductPath");
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
      if (!is_accessible_share(share:share)) accessibleshare = FALSE;
      else accessibleshare = TRUE;
    }
    if (accessibleshare)
    {
      path = path - 'Wordconv.exe';

      if (hotfix_check_fversion(path:path, file:"wordcnv.dll", version:"12.0.6539.5000", bulletin:bulletin, kb:'2277947') == HCF_OLDER)
      {
        vuln++;
      }
    }
  }
  hotfix_check_fversion_end();
}

if (vuln)
{
    set_kb_item(name:'SMB/Missing/MS10-056', value:TRUE);
    hotfix_security_hole();
    exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
