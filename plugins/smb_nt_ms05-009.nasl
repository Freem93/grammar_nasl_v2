#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(16328);
 script_version("$Revision: 1.38 $");
 script_cvs_date("$Date: 2016/01/28 22:37:17 $");

 script_cve_id("CVE-2004-1244", "CVE-2004-0597");
 script_bugtraq_id(12485, 12506);
 script_osvdb_id(8312, 8326, 13597);
 script_xref(name:"MSFT", value:"MS05-009");
 script_xref(name:"CERT", value:"259890");
 script_xref(name:"CERT", value:"388984");
 script_xref(name:"CERT", value:"817368");
 script_xref(name:"EDB-ID", value:"25094");
 script_xref(name:"EDB-ID", value:"393");
 script_xref(name:"EDB-ID", value:"389");

 script_name(english:"MS05-009: Vulnerability in PNG Processing Could Allow Remote Code Execution (890261)");
 script_summary(english:"Checks the version of Media Player");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the Media
Player.");
 script_set_attribute(attribute:"description", value:
"The remote host is running either Windows Media Player 9 or MSN
Messenger.

There is a vulnerability in the remote version of this software that
could allow an attacker to execute arbitrary code on the remote host.

To exploit this flaw, one attacker would need to set up a rogue PNG
image and send it to a victim on the remote host.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms05-009");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and
2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/04");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/02/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/08");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:msn_messenger");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:windows_media_player");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:windows_messenger");
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
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS05-009';

kbs = make_list("885492", "887472");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'1,2', win2003:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

progfile = hotfix_get_programfilesdir();
if (!progfile) exit(1, "Failed to get the Program Files directory.");

share = hotfix_path2share(path:progfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"5.2", sp:0, file:"Wmp.dll", version:"9.0.0.3250", min_version:"9.0.0.0", dir:"\system32", bulletin:bulletin, kb:'885492') ||
  hotfix_is_vulnerable(os:"5.2", file:"Msmsgs.exe", version:"5.1.0.639", min_version:"5.1.0.0", path:progfile, dir:"\Messenger") ||
  hotfix_is_vulnerable(os:"5.1", sp:1, file:"Wmp.dll", version:"9.0.0.3250", min_version:"9.0.0.0", dir:"\system32", bulletin:bulletin, kb:'885492') ||
  hotfix_is_vulnerable(os:"5.1", sp:1, file:"Msmsgs.exe", version:"4.7.0.2010", min_version:"4.7.0.0", path:progfile, dir:"\Messenger", bulletin:bulletin, kb:'887472') ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Msmsgs.exe", version:"4.7.0.3001", min_version:"4.7.0.3000", path:progfile, dir:"\Messenger", bulletin:bulletin, kb:'887472') ||
  hotfix_is_vulnerable(os:"5.1", file:"Msmsgs.exe", version:"5.1.0.639", min_version:"5.1.0.0", path:progfile, dir:"\Messenger") ||
  hotfix_is_vulnerable(os:"5.0", file:"Msmsgs.exe", version:"5.1.0.639", min_version:"5.1.0.0", path:progfile, dir:"\Messenger") ||
  hotfix_is_vulnerable(os:"5.0", file:"Wmp.dll", version:"9.0.0.3250", min_version:"9.0.0.0", dir:"\system32", bulletin:bulletin, kb:'885492')
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
