#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(26962);
 script_version("$Revision: 1.24 $");
 script_cvs_date("$Date: 2015/04/23 21:11:56 $");

 script_cve_id("CVE-2007-3897");
 script_bugtraq_id(25908);
 script_osvdb_id(37631);
 script_xref(name:"MSFT", value:"MS07-056");

 script_name(english:"MS07-056: Cumulative Security Update for Outlook Express and Windows Mail (941202)");
 script_summary(english:"Determines the presence of update 941202");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the email
client.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Outlook Express that
contains several security flaws that could allow an attacker to execute
arbitrary code on the remote host.

To exploit this flaw, an attacker would need to send a malformed email
to a victim on the remote host and have him open it.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS07-056");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Outlook Express and Windows
Mail.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/10/09");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/10/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/09");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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

bulletin = 'MS07-056';
kb = '941202';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2', win2003:'1,2', vista:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Inetcomm.dll", version:"6.0.6000.16545", dir:"\system32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Inetcomm.dll", version:"6.0.3790.4133", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:1, file:"Inetcomm.dll", version:"6.0.3790.2992", dir:"\system32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Inetcomm.dll", version:"6.0.2900.3198", dir:"\system32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.0",       file:"Inetcomm.dll", version:"6.0.2800.1914", min_version:"6.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0",	    file:"Inetcomm.dll", version:"5.50.4980.1600", dir:"\system32", bulletin:bulletin, kb:kb)
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
