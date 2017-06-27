#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11300);
 script_version("$Revision: 1.37 $");
 script_cvs_date("$Date: 2017/05/26 15:15:35 $");

 script_cve_id("CVE-2002-0724");
 script_bugtraq_id(5556);
 script_osvdb_id(2074);
 script_xref(name:"MSFT", value:"MS02-045");
 script_xref(name:"MSKB", value:"326830");

 script_name(english:"MS02-045: Unchecked buffer in Network Share Provider (326830)");
 script_summary(english:"Checks for MS Hotfix Q326830");

 script_set_attribute(attribute:"synopsis", value:"It is possible to crash the remote host.");
 script_set_attribute(attribute:"description", value:
"Due to a flaw in Microsoft's SMB implementation, the remote host is
vulnerable to a denial of service attack.  By sending a specially
crafted packet request, an attacker could launch a denial of service,
causing the affected host to crash.

Note that this vulnerability is not exploitable without credentials
unless anonymous access has been disabled.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms02-045");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows NT, 2000 and XP.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/08/22");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/08/22");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/01");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");
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

bulletin = 'MS02-045';
kb = '326830';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(nt:'6', win2k:'2,3', xp:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"5.1", sp:0, file:"Xactsrv.dll", version:"5.1.2600.50", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", file:"Xactsrv.dll", version:"5.0.2195.5971", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"4.0", file:"Xactsrv.dll", version:"4.0.1381.7181", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"4.0", file:"Xactsrv.dll", version:"4.0.1381.33538", min_version:"4.0.1381.33000", dir:"\system32", bulletin:bulletin, kb:kb)
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


