#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(19403);
 script_version("$Revision: 1.29 $");
 script_cvs_date("$Date: 2015/04/23 21:04:50 $");

 script_cve_id("CVE-2005-0058");
 script_bugtraq_id(14518);
 script_osvdb_id(18606);
 script_xref(name:"MSFT", value:"MS05-040");

 script_name(english:"MS05-040: Vulnerability in Telephony Service Could Allow Remote Code Execution (893756)");
 script_summary(english:"Determines the presence of update 893756");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host due to a flaw in the
Telephony service.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Telephony service that is
vulnerable to a security flaw that could allow an attacker to execute
arbitrary code and take control of the remote host.

On Windows 2000 and Windows 2003 the server must be enabled and only
authenticated user can try to exploit this flaw.

On Windows 2000 Pro and Windows XP this is a local elevation of
privilege vulnerability.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms05-040");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/09");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/08/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/09");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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

bulletin = 'MS05-040';
kb = '893756';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4', xp:'1,2', win2003:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"5.2", sp:0, file:"Tapisrv.dll", version:"5.2.3790.366", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:1, file:"Tapisrv.dll", version:"5.2.3790.2483", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:1, file:"Tapisrv.dll", version:"5.1.2600.1715", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Tapisrv.dll", version:"5.1.2600.2716", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", sp:4, file:"Tapisrv.dll", version:"5.0.2195.7057", dir:"\system32", bulletin:bulletin, kb:kb)
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
