#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15966);
 script_version("$Revision: 1.28 $");
 script_cvs_date("$Date: 2015/04/23 21:04:49 $");

 script_cve_id("CVE-2004-0571", "CVE-2004-0901");
 script_bugtraq_id(11927, 11929);
 script_osvdb_id(12373, 12375);
 script_xref(name:"MSFT", value:"MS04-041");

 script_name(english:"MS04-041: Vulnerabilities in WordPad (885836)");
 script_summary(english:"Checks the remote registry for MS04-041");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code can be executed on the remote host through WordPad.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of Microsoft WordPad that is
vulnerable to two security flaws.

To exploit these flaws an attacker would need to send a malformed Word
file to a victim on the remote host and wait for him to open the file
using WordPad.

Opening the file with WordPad will trigger a buffer overflow that could
allow an attacker to execute arbitrary code on the remote host with the
privileges of the user.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms04-041");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/12/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/14");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

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

bulletin = 'MS04-041';
kb = '885836';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(nt:'6', win2k:'3,4', xp:'1,2', win2003:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

path = hotfix_get_programfilesdir();
if (!path) exit(1, "Failed to get the Program Files directory.");

share = hotfix_path2share(path:path);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

path += "\Windows NT\Accessories";

if (
  hotfix_is_vulnerable(os:"5.2", sp:0, file:"Wordpad.exe", version:"5.2.3790.224", path:path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:1, file:"Wordpad.exe", version:"5.1.2600.1606", path:path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Mswrd6.wpc", version:"10.0.803.2", path:path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", file:"Wordpad.exe", version:"5.0.2195.6991", path:path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"4.0", file:"Wordpad.exe", version:"4.0.1381.7312", path:path, bulletin:bulletin, kb:kb)
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
