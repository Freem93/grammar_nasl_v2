#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25488);
 script_version("$Revision: 1.29 $");
 script_cvs_date("$Date: 2016/05/06 17:11:37 $");

 script_cve_id("CVE-2007-2219");
 script_bugtraq_id(24370);
 script_osvdb_id(35341);
 script_xref(name:"MSFT", value:"MS07-035");
 script_xref(name:"CERT", value:"457281");

 script_name(english:"MS07-035: Vulnerability in Win 32 API Could Allow Remote Code Execution (935839)");
 script_summary(english:"Determines if hotfix 935839 has been installed");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the Win32
API.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Win32 API that is vulnerable
to a security flaw that could allow a local user to gain elevated
privileges, and might allow a remote attacker to execute arbitrary code
on the host.

To exploit the flaw, an attacker would need to find a way to misuse the
Win32 API.  One way of doing so would be to lure a user on the remote
host into visiting a specially crafted web page.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS07-035");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and
2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/06/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/12");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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

bulletin = 'MS07-035';
kb = '935839';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2', win2003:'1,2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Kernel32.dll", version:"5.2.3790.4062", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:1, file:"Kernel32.dll", version:"5.2.3790.2919", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Kernel32.dll", version:"5.1.2600.3119", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", file:"Kernel32.dll", version:"5.0.2195.7135", dir:"\system32", bulletin:bulletin, kb:kb)
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
