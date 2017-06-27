#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(13640);
 script_version("$Revision: 1.39 $");
 script_cvs_date("$Date: 2015/04/23 21:04:49 $");

 script_cve_id("CVE-2004-0212");
 script_bugtraq_id(10708);
 script_osvdb_id(7798);
 script_xref(name:"CERT", value:"228028");
 script_xref(name:"MSFT", value:"MS04-022");

 script_name(english:"MS04-022: Task Scheduler Vulnerability (841873)");
 script_summary(english:"Checks for ms04-022 over the registry");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
client.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows which contains a flaw
in the task scheduler that could lead to arbitrary execution of commands
on the remote host.

To exploit this vulnerability, an attacker would need to lure a user
on the remote host to take certain steps to execute a .job file, or to
visit a rogue website, arbitrary commands could then be used on the
remote host.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms04-022");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows 2000 and XP.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/07/13");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/07/13");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/13");

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

bulletin = 'MS04-022';
kb = '841873';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(nt:'6', win2k:'2,4', xp:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"5.1", sp:1, file:"Mstask.dll", version:"5.1.2600.1564", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:0, file:"Mstask.dll", version:"5.1.2600.155", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", file:"Mstask.dll", version:"4.71.2195.6920", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"4.0", file:"Mstask.dll", version:"4.71.1979.1", dir:"\system32", bulletin:bulletin, kb:kb)
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
