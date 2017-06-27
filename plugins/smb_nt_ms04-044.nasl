#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(15963);
 script_version("$Revision: 1.32 $");
 script_cvs_date("$Date: 2015/04/23 21:04:49 $");

 script_cve_id("CVE-2004-0893", "CVE-2004-0894");
 script_bugtraq_id(11913, 11914);
 script_osvdb_id(12372, 12376);
 script_xref(name:"MSFT", value:"MS04-044");

 script_name(english:"MS04-044: Vulnerabilities in Windows Kernel and LSASS (885835)");
 script_summary(english:"Checks the remote registry for MS04-044");

 script_set_attribute(attribute:"synopsis", value:"Local users can elevate their privileges on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host is running version of the NT kernel and LSASS which
could allow a local user to gain elevated privileged.

An attacker who has the ability to execute arbitrary commands on the
remote host could exploit these flaws to gain SYSTEM privileges.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms04-044");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/12/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/12/14");

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
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS04-044';
kb = '885835';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(nt:'6', win2k:'3,4', xp:'1,2', win2003:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"5.2", sp:0, file:"Lsasrv.dll", version:"5.2.3790.220", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:1, file:"Lsasrv.dll", version:"5.1.2600.1597", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Lsasrv.dll", version:"5.1.2600.2525", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", file:"Lsasrv.dll", version:"5.0.2195.6987", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"4.0", file:"Ntoskrnl.exe", version:"4.0.1381.7268", dir:"\system32", bulletin:bulletin, kb:kb)
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
