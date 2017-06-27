#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(22030);
 script_version("$Revision: 1.31 $");
 script_cvs_date("$Date: 2015/04/23 21:04:50 $");

 script_cve_id("CVE-2006-2372");
 script_bugtraq_id(18923);
 script_osvdb_id(27151);
 script_xref(name:"CERT", value:"257164");
 script_xref(name:"MSFT", value:"MS06-036");

 script_name(english:"MS06-036: Vulnerability in DHCP Client Service Could Allow Remote Code Execution (914388)");
 script_summary(english:"Determines the presence of update 914388");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host due to a flaw in the
DHCP client.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a DHCP client that is vulnerable to a buffer
overrun attack when receiving a malformed response to a DHCP request.

An attacker could exploit this flaw to execute arbitrary code on the
remote host with 'SYSTEM' privileges.

Typically, the attacker would need to be on the same physical subnet
as this victim to exploit this flaw.  Also, the victim needs to be
configured to use DHCP.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms06-036");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/11");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/07/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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

bulletin = 'MS06-036';
kb = '914388';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'1,2', win2003:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if ( hotfix_is_vulnerable(os:"5.2", sp:0, file:"Dhcpcsvc.dll", version:"5.2.3790.536", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.2", sp:1, file:"Dhcpcsvc.dll", version:"5.2.3790.2706", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.1", sp:1, file:"Dhcpcsvc.dll", version:"5.1.2600.1847", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.1", sp:2, file:"Dhcpcsvc.dll", version:"5.1.2600.2912", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.0", file:"Dhcpcsvc.dll", version:"5.0.2195.7085", dir:"\system32", bulletin:bulletin, kb:kb) )
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
