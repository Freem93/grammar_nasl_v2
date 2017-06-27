#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66418);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/12/01 15:02:06 $");

  script_cve_id("CVE-2013-1335");
  script_bugtraq_id(59759);
  script_osvdb_id(93315);
  script_xref(name:"MSFT", value:"MS13-043");

  script_name(english:"MS13-043: Vulnerability in Microsoft Word Could Allow Remote Code Execution (2830399)");
  script_summary(english:"Checks file versions");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A Microsoft Office component installed on the remote host is affected
by a code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Office and/or Microsoft Word Viewer installed on the
remote host is affected by a remote code execution vulnerability due to
the way that Microsoft Word parses content in Word files.  To exploit
this issue, an attacker would need to trick a user into opening a
specially crafted file or email message with an affected version of
Microsoft Office software."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-043");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Office 2003 and Microsoft
Word Viewer."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS13-043';
kbs = make_list(2810046, 2817361);
if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

vuln = FALSE;
# Word
installs = get_kb_list("SMB/Office/Word/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    info = '';
    version = install - 'SMB/Office/Word/' - '/ProductPath';
    path = installs[install];
    if (isnull(path)) path = "n/a";

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);


    # Word 2003 SP3
    if (ver[0] == 11 && ver[1] == 0 && ver[2] >= 8173)
    {
      if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8402)
      {
        info =
          '\n  Product           : Word 2003' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 11.0.8402.0' + '\n';
        kb = "2810046";
      }
    }
  }

  if (info)
  {
    hotfix_add_report(info, bulletin:bulletin, kb:kb);
    vuln = TRUE;
  }
}

# Word Viewer
installs = get_kb_list("SMB/Office/WordViewer/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    info = "";
    version = install - 'SMB/Office/WordViewer/' - '/ProductPath';
    path = installs[install];
    if (isnull(path)) path = "n/a";

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

    if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8402)
    {
      info =
        '\n  Product           : Word Viewer' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 11.0.8402.0' + '\n';
      kb = "2817361";
    }

    if (info)
    {
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
      vuln = TRUE;
    }
  }
}

if (vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
