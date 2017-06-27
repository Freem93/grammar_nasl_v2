#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(22183);
 script_version("$Revision: 1.32 $");
 script_cvs_date("$Date: 2016/12/09 20:54:59 $");

 script_cve_id("CVE-2006-3440", "CVE-2006-3441");
 script_bugtraq_id(19319, 19404);
 script_osvdb_id(27843, 27844);
 script_xref(name:"CERT", value:"908276");
 script_xref(name:"CERT", value:"794580");
 script_xref(name:"MSFT", value:"MS06-041");

 script_name(english:"MS06-041: Vulnerability in DNS Resolution Could Allow Remote Code Execution (920683)");
 script_summary(english:"Determines the presence of update 920683");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host due to a flaw in the
DNS client.");
 script_set_attribute(attribute:"description", value:
"The remote host is vulnerable to a buffer overrun in the DNS client
service that could allow an attacker to execute arbitrary code on the
remote host with SYSTEM privileges.

To exploit this vulnerability, an attacker would need to set up a
rogue DNS server to reply to the client with a specially crafted
packet.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms06-041");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/08");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/08/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/08");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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

bulletin = 'MS06-041';
kb = '920683';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'1,2', win2003:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
     hotfix_is_vulnerable(os:"5.2", sp:0, file:"Dnsapi.dll", version:"5.2.3790.558", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.2", sp:1, file:"Dnsapi.dll", version:"5.2.3790.2745", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.1", sp:1, file:"Dnsapi.dll", version:"5.1.2600.1863", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.1", sp:2, file:"Dnsapi.dll", version:"5.1.2600.2938", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.0", file:"Dnsapi.dll", version:"5.0.2195.7100", dir:"\system32", bulletin:bulletin, kb:kb) ||

     hotfix_is_vulnerable(os:"5.2", sp:0, file:"Rasadhlp.dll", version:"5.2.3790.558", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.2", sp:1, file:"Rasadhlp.dll", version:"5.2.3790.2745", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.1", sp:1, file:"Rasadhlp.dll", version:"5.1.2600.1863", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.1", sp:2, file:"Rasadhlp.dll", version:"5.1.2600.2938", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.0", file:"Rasadhlp.dll", version:"5.0.2195.7098", dir:"\system32", bulletin:bulletin, kb:kb) )
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
