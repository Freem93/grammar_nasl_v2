#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(12207);
 script_version("$Revision: 1.33 $");
 script_cvs_date("$Date: 2015/04/23 21:04:49 $");

 script_cve_id("CVE-2004-0197");
 script_bugtraq_id(10112);
 script_osvdb_id(5241);
 script_xref(name:"MSFT", value:"MS04-014");

 script_name(english:"MS04-014: Microsoft Hotfix (credentialed check) (837001)");
 script_summary(english:"Checks for ms04-014");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through database
engine.");
 script_set_attribute(attribute:"description", value:
"The remote host has a bug in its Microsoft Jet Database Engine
(837001).

An attacker could exploit one of these flaws to execute arbitrary code
on the remote system.

To exploit this flaw, an attacker would need the ability to craft a
specially malformed database query and have this engine execute it.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms04-014");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/13");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/04/13");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/04/13");

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

bulletin = 'MS04-014';
kb = '837001';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(nt:'6', win2k:'2,4', xp:'0,1', win2003:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"5.2", sp:0, file:"Msjet40.dll", version:"4.0.8618.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:1, file:"Msjet40.dll", version:"4.0.8618.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:0, file:"Msjet40.dll", version:"4.0.8618.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", file:"Msjet40.dll", version:"4.0.8618.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"4.0", file:"Msjet40.dll", version:"4.0.8618.0", dir:"\system32", bulletin:bulletin, kb:kb)
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
