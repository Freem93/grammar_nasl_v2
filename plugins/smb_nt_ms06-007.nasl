#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(20907);
 script_version("$Revision: 1.29 $");
 script_cvs_date("$Date: 2015/04/23 21:04:50 $");

 script_cve_id("CVE-2006-0021");
 script_bugtraq_id(16645);
 script_osvdb_id(23133);
 script_xref(name:"CERT", value:"839284");
 script_xref(name:"MSFT", value:"MS06-007");

 script_name(english:"MS06-007: Vulnerability in TCP/IP Could Allow Denial of Service (913446)");
 script_summary(english:"Checks the remote registry for 913446");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to crash the remote host due to a flaw in the TCP/IP
stack.");
 script_set_attribute(attribute:"description", value:
"The remote host runs a version of Windows with a flaw in its TCP/IP
stack that could allow an attacker to perform a denial of service attack
against the remote host.

To exploit this vulnerability, an attacker needs to send a specially
crafted IGMP packet to the remote host.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms06-007");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and
2003");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(119);

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/02/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/02/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/14");

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

bulletin = 'MS06-007';
kbs = make_list("913446");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'1,2', win2003:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

kb = '913446';

if ( hotfix_is_vulnerable(os:"5.2", sp:0, file:"Tcpip.sys", version:"5.2.3790.468",  dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.2", sp:1, file:"Tcpip.sys", version:"5.2.3790.2617", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.1", sp:1, file:"Tcpip.sys", version:"5.1.2600.1792", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.1", sp:2, file:"Tcpip.sys", version:"5.1.2600.2827", dir:"\system32\drivers", bulletin:bulletin, kb:kb) )
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_warning();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
