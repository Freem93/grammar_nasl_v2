#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(16329);
 script_version("$Revision: 1.32 $");
 script_cvs_date("$Date: 2015/05/07 12:06:03 $");

 script_cve_id("CVE-2004-1319");
 script_bugtraq_id(11950);
 script_osvdb_id(12424);
 script_xref(name:"MSFT", value:"MS05-013");
 script_xref(name:"CERT", value:"356600");

 script_name(english:"MS05-013: Vulnerability in the DHTML Editing Component may allow code execution (891781)");
 script_summary(english:"Checks for KB 891781 via the registry");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
client.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows which contains a flaw
in the DHTML Editing Component ActiveX Control.

An attacker could exploit this flaw to execute arbitrary code on the
remote host.

To exploit this flaw, an attacker would need to construct a malicious
web page and lure a victim into visiting it.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms05-013");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and
2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/15");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/02/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/08");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl" , "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS05-013';
kb = '891781';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'3,4', xp:'1,2', win2003:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

path = hotfix_get_commonfilesdir();
if (!path) exit(1, "Failed to get the Common Files directory.");

share = hotfix_path2share(path:path);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"5.2", sp:0, file:"Dhtmled.ocx", version:"6.1.0.9231", path:path, dir:"\Microsoft Shared\Triedit", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", file:"Dhtmled.ocx", version:"6.1.0.9232", path:path, dir:"\Microsoft Shared\Triedit", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", file:"Dhtmled.ocx", version:"6.1.0.9232", path:path, dir:"\Microsoft Shared\Triedit", bulletin:bulletin, kb:kb)
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
