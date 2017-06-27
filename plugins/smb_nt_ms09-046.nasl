#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40889);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2015/04/23 21:11:58 $");

  script_cve_id("CVE-2009-2519");
  script_bugtraq_id(36280);
  script_osvdb_id(57798);
  script_xref(name:"IAVA", value:"2009-A-0075");
  script_xref(name:"MSFT", value:"MS09-046");

  script_name(english:"MS09-046: Vulnerability in DHTML Editing Component ActiveX Control Could Allow Remote Code Execution (956844)");
  script_summary(english:"Checks version of triedit.dll");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through an ActiveX
control.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing Security Update 956844.  The DHTML Editing
Component ActiveX Control on the remote host has a remote code execution
vulnerability.  A remote attacker could exploit this by tricking a user
into viewing a specially crafted web page, resulting in the execution of
arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-046");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, and
2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}


include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS09-046';
kb = '956844';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

prog_files = hotfix_get_programfilesdir();
if (!prog_files) exit(1, "Can't determine location of Program Files.");

share = hotfix_path2share(path:prog_files);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

dir = prog_files + "\Common Files\Microsoft Shared\Triedit";

dir_x64 = NULL;
prog_files_x64 = hotfix_get_programfilesdirx86();
if (!isnull(prog_files_x64))
{
  if (tolower(prog_files_x64[0]) != tolower(prog_files[0]))
  {
    share = hotfix_path2share(path:prog_files_x64);
    if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);
  }
  dir_x64 = prog_files_x64 + "\Common Files\Microsoft Shared\Triedit";
}


if (
  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x86", file:"Triedit.dll", version:'6.1.0.9246',   path:dir, bulletin:bulletin, kb:kb) ||
  (
    !isnull(dir_x64) &&
    hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"Triedit.dll", version:'6.1.0.9246',   path:dir_x64, bulletin:bulletin, kb:kb)
  ) ||

  # Windows XP
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Triedit.dll", version:'6.1.0.9246',   path:dir, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Triedit.dll", version:'6.1.0.9246',   path:dir, bulletin:bulletin, kb:kb) ||
  (
    !isnull(dir_x64) &&
    hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"Triedit.dll", version:'6.1.0.9246',   path:dir_x64, bulletin:bulletin, kb:kb)
  ) ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0", file:"Triedit.dll", version:'6.1.0.9235', path:dir, bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
