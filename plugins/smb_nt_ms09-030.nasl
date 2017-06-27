#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(39793);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2015/04/23 21:11:58 $");

  script_cve_id("CVE-2009-0566");
  script_bugtraq_id(35599);
  script_osvdb_id(55838);
  script_xref(name:"MSFT", value:"MS09-030");

  script_name(english:"MS09-030: Vulnerability in Microsoft Office Publisher Could Allow Remote Code Execution (969516)");
  script_summary(english:"Checks versions of Mspub.exe and associated DLLs");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to execute arbitrary code on the remote Windows host
using Microsoft Office Publisher.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of Microsoft Office
Publisher that fails to properly calculate object handler data when
opening, importing, or converting files created in versions older than
Microsoft Office Publisher 2007, which could lead to memory
corruption.

If an attacker can trick a user on the affected system into opening a
specially crafted Publisher file with Microsoft Office Publisher, he
may be able to leverage this issue to execute arbitrary code subject
to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-030");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Publisher 2007.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_nt_ms02-031.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS09-030';
kb = '969693';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

vuln = 0;
installs = get_kb_list_or_exit("SMB/Office/Publisher/*/ProductPath");
foreach install (keys(installs))
{
  if ("12.0" >< install)
  {
    sp = get_kb_item("SMB/Office/12.0/SP");
    if (isnull(sp) || sp != 1) break;
    version = install - 'SMB/Office/Publisher/' - '/ProductPath';
    path = installs[install];
    if (isnull(path)) path = 'n/a';

    ver = split(ver, sep:'.', keep:FALSE);
    for (i=0; i < max_index(ver); i++)
      ver[i] = int(ver[i]);

    if (ver[0] == 12 && ver[1] == 0 && ver[2] < 6501)
    {
      vuln++;
      info =
        '\n  Product           : Publisher 2007' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 12.0.6501.5000\n';
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
    }
  }
}

programfiles = hotfix_get_officeprogramfilesdir(officever:"12.0");
if (programfiles)
{
  share = hotfix_path2share(path:programfiles);
  if (is_accessible_share(share:share))
  {
    path = programfiles + "\Microsoft Office\Office12";

    if (
      hotfix_check_fversion(file:"Morph9.dll",  path:path, version:"12.0.6500.5000", bulletin:bulletin, kb:kb) == HCF_OLDER ||
      hotfix_check_fversion(file:"Prtf9.dll",   path:path, version:"12.0.6500.5000", bulletin:bulletin, kb:kb) == HCF_OLDER ||
      hotfix_check_fversion(file:"Ptxt9.dll",   path:path, version:"12.0.6500.5000", bulletin:bulletin, kb:kb) == HCF_OLDER ||
      hotfix_check_fversion(file:"Pubconv.dll", path:path, version:"12.0.6501.5000", bulletin:bulletin, kb:kb) == HCF_OLDER ||
      hotfix_check_fversion(file:"Pubtrap.dll", path:path, version:"12.0.6500.5000", bulletin:bulletin, kb:kb) == HCF_OLDER
    )
    {
      vuln++;
    }
  }
}
hotfix_check_fversion_end();
if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
