#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(22185);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2015/04/23 21:04:50 $");

 script_cve_id("CVE-2006-2766");
 script_bugtraq_id(18198);
 script_osvdb_id(25949);
 script_xref(name:"CERT", value:"891204");
 script_xref(name:"MSFT", value:"MS06-043");

 script_name(english:"MS06-043: Vulnerability in Microsoft Windows Could Allow Remote Code Execution (920214)");
 script_summary(english:"Determines the presence of update 920214");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the email
client.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Outlook Express
that contains a security flaw that could allow an attacker to execute
arbitrary code on the remote host.

To exploit this flaw, an attacker would need to send a malformed HTML
email to a victim on the remote host and have him open it.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms06-043");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Outlook Express.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/31");
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

bulletin = 'MS06-043';
kb = '920214';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_NOTE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'2', win2003:'1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if ( hotfix_is_vulnerable(os:"5.2", sp:1, file:"Inetcomm.dll", version:"6.0.3790.2757", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.1", sp:2, file:"Inetcomm.dll", version:"6.0.2900.2962", dir:"\system32", bulletin:bulletin, kb:kb) )
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_note();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
