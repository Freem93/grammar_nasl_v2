#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69325);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/06 17:11:38 $");

  script_cve_id("CVE-2013-3181");
  script_bugtraq_id(61697);
  script_osvdb_id(96193);
  script_xref(name:"MSFT", value:"MS13-060");
  script_xref(name:"IAVA", value:"2013-A-0164");

  script_name(english:"MS13-060: Vulnerability in Unicode Scripts Processor Could Allow Remote Code Execution (2850869)");
  script_summary(english:"Checks version of usp10.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"It is possible to execute arbitrary code on the remote Windows host
using the Unicode Scripts Processor."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Microsoft Windows installed on the remote host includes
a vulnerable version of the Unicode Script Processor, also known as
Uniscribe.  Some font types are not parsed correctly, which can result
in memory corruption.  An attacker could exploit this by tricking a user
into viewing a specially crafted web page or opening a file containing
malicious OpenType fonts, resulting in arbitrary code execution."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-060");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows XP and 2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS13-060';
kb = '2850869';

kbs = make_list(kb);
if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);
if (hotfix_check_sp_range(xp:'3', win2003:'2') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

root = hotfix_get_systemroot();
if (!root)
  audit(AUDIT_FN_FAIL, 'hotfix_get_systemroot');
share = hotfix_path2share(path:root);
if (!is_accessible_share(share:share))
  audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 2003 / XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"usp10.dll", version:"1.422.3790.5194",  dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"usp10.dll", version:"1.420.2600.6421", dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:'SMB/Missing/' + bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}

