#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(22187);
 script_version("$Revision: 1.32 $");
 script_cvs_date("$Date: 2015/04/23 21:04:50 $");

 script_cve_id("CVE-2006-3281");
 script_bugtraq_id(19389);
 script_osvdb_id(26957);
 script_xref(name:"CERT", value:"655100");
 script_xref(name:"MSFT", value:"MS06-045");

 script_name(english:"MS06-045: Vulnerability in Windows Explorer Could Allow Remote Code Execution (921398)");
 script_summary(english:"Determines the presence of update 921398");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web or
email client.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows that contains a flaw
in the Windows Explorer Drag & Drop handler.

An attacker may be able to execute arbitrary code on the remote host
by constructing a malicious script and enticing a victim to visit a
website or view a specially crafted email message and save a file.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms06-045");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/27");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/08/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/08");

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

bulletin = 'MS06-045';
kb = '921398';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'1,2', win2003:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if ( hotfix_is_vulnerable(os:"5.2", sp:0, file:"Shell32.dll", version:"6.0.3790.559", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.2", sp:1, file:"Shell32.dll", version:"6.0.3790.2746", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.1", sp:1, file:"Shell32.dll", version:"6.0.2800.1873", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.1", sp:2, file:"Shell32.dll", version:"6.0.2900.2951", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.0", file:"Shell32.dll", version:"5.0.3900.7105", dir:"\system32", bulletin:bulletin, kb:kb) )
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
