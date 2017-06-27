#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(16124);
 script_version("$Revision: 1.45 $");
 script_cvs_date("$Date: 2016/12/09 20:54:59 $");

 script_cve_id("CVE-2004-1049", "CVE-2004-1305", "CVE-2005-0416");
 script_bugtraq_id(12095, 12233);
 script_osvdb_id(12623, 12624, 12842, 16430);
 script_xref(name:"MSFT", value:"MS05-002");
 script_xref(name:"CERT", value:"625856");
 script_xref(name:"CERT", value:"697136");
 script_xref(name:"EDB-ID", value:"721");

 script_name(english:"MS05-002: Cursor and Icon Format Handling Code Execution (891711)");
 script_summary(english:"Checks version of User32.dll");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web or
email client.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Windows kernel that is
affected by a security flaw in the way that cursors and icons are
handled.  An attacker may be able to execute arbitrary code on the
remote host by constructing a malicious web page and entice a victim to
visit this web page.  An attacker may send a malicious email to the
victim to exploit this flaw too.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms05-002");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/20");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/01/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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

bulletin = 'MS05-002';
kb = '891711';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(nt:'6', win2k:'3,4', xp:'1', win2003:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"5.2", sp:0, file:"User32.dll", version:"5.2.3790.245", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:1, file:"User32.dll", version:"5.1.2600.1617", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", file:"User32.dll", version:"5.0.2195.7017", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"4.0", file:"User32.dll", version:"4.0.1381.7342", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"4.0", file:"User32.dll", version:"4.0.1381.33630", min_version:"4.0.1381.33000", dir:"\system32", bulletin:bulletin, kb:kb)
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
