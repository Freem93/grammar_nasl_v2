#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42442);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id("CVE-2009-3135");
  script_bugtraq_id(36950);
  script_osvdb_id(59857);
  script_xref(name:"MSFT", value:"MS09-068");

  script_name(english:"MS09-068: Vulnerability in Microsoft Office Word Could Allow Remote Code Execution (976307)");
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
Word Viewer that is affected by a memory corruption vulnerability.  If
an attacker can trick a user on the affected host into opening a
specially crafted Word file, he could leverage this issue to execute
arbitrary code subject to the user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-068");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Office XP, Word 2003, and
Word Viewer."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
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

bulletin = 'MS09-068';
kbs = make_list("973443", "973444", "973866");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


info = "";

# Word.
vuln = 0;
kb = '';
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

    # Word 2003.
    if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8313)
    {
      office_sp = get_kb_item("SMB/Office/2003/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        vuln++;
        info =
          '\n  Product           : Word 2003' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 11.0.8313.0\n';
        kb = '973443';
        hotfix_add_report(info, bulletin:bulletin, kb:kb);
      }
    }
    # Word 2002.
    else if (ver[0] == 10 && ver[1] == 0 && ver[2] < 6856)
    {
      office_sp = get_kb_item("SMB/Office/XP/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        vuln++;
        info =
          '\n  Product           : Word 2002' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 10.0.6856.0\n';
        kb = '973444';
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
    if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8313)
    {
      vuln++;
      info =
        '\n  Product           : Word Viewer / Word Viewer 2003' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 11.0.8313.0\n';
      kb = '973866';
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
