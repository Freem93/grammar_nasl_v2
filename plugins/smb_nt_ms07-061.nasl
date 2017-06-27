#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(28183);
 script_version("$Revision: 1.34 $");
 script_cvs_date("$Date: 2016/05/06 17:11:37 $");

 script_cve_id("CVE-2007-3896");
 script_bugtraq_id(25945);
 script_osvdb_id(41090);
 script_xref(name:"MSFT", value:"MS07-061");
 script_xref(name:"CERT", value:"403150");
 script_xref(name:"EDB-ID", value:"30645");

 script_name(english:"MS07-061: Vulnerability in Windows URI Handling Could Allow Remote Code Execution (943460)");
 script_summary(english:"Determines the presence of update 943460");

 script_set_attribute(attribute:"synopsis", value:
"Vulnerabilities in the Windows Shell may allow a user to elevate his
privileges.");
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a version of the Windows Shell
that contains a vulnerability in the way it handles URI.

An attacker might use this flaw to execute arbitrary commands on the
remote host using attack vectors such as IE or other tools.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS07-061");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows XP and 2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_cwe_id(20);

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/25");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/11/13");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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

bulletin = 'MS07-061';
kb = '943460';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'2', win2003:'1,2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"shell32.dll", version:"6.0.3790.4184", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:1, file:"shell32.dll", version:"6.0.3790.3033", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"shell32.dll", version:"6.0.2900.3241", dir:"\system32", bulletin:bulletin, kb:kb)
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
