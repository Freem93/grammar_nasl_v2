#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(40559);
 script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2015/04/23 21:11:58 $");

 script_cve_id("CVE-2009-1922");
 script_bugtraq_id(35969);
 script_osvdb_id(56901);
 script_xref(name:"MSFT", value:"MS09-040");

 script_name(english:"MS09-040: Vulnerability in Message Queuing Could Allow Elevation of Privilege (971032)");
 script_summary(english:"Determines if hotfix 971032 has been installed");

 script_set_attribute(attribute:"synopsis", value:"Users can elevate their privileges on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote version of Windows is affected by a vulnerability in the
Microsoft Message Queuing Service (MSMQ).

An attacker with valid login credentials may exploit this flaw to
execute arbitrary code on the remote host with the SYSTEM privileges
and therefore elevate his privileges.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-040");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003 and
Vista.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(264);

 script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/11");
 script_set_attribute(attribute:"patch_publication_date", value:"2009/08/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows : Microsoft Bulletins");

 script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

 script_dependencies("smb_hotfixes.nasl" , "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}


include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS09-040';
kb = '971032';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2', win2003:'2', vista:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"5.0", file:"Mqqm.dll", version:"5.0.0.808", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Mqqm.dll", version:"5.1.0.1111", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mqqm.dll", version:"5.2.2007.4530", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Mqqm.dll", version:"6.0.6000.16871", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Mqqm.dll", version:"6.0.6000.21068", min_version:"6.0.6000.21000", dir:"\system32", bulletin:bulletin, kb:kb)
)
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
