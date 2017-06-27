#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(40560);
 script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2015/04/23 21:11:58 $");

 script_cve_id("CVE-2009-1544");
 script_bugtraq_id(35972);
 script_osvdb_id(56902);
 script_xref(name:"MSFT", value:"MS09-041");
 script_xref(name:"IAVB", value:"2009-B-0035");

 script_name(english:"MS09-041: Vulnerability in Workstation Service Could Allow Elevation of Privilege (971657)");
 script_summary(english:"Checks for hotfix 971657");

 script_set_attribute(attribute:"synopsis", value:"Users can elevate their privileges on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the 'Workstation' service that
contains a memory corruption vulnerability that might allow an attacker
with valid credentials to execute arbitrary code on the remote host.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-041");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista and
Server 2008.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(399);

 script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/11");
 script_set_attribute(attribute:"patch_publication_date", value:"2009/08/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"stig_severity", value:"II");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows : Microsoft Bulletins");

 script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

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

bulletin = 'MS09-041';
kb = '971657';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'2,3', win2003:'2', vista:'0,2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"wkssvc.dll", version:"5.1.2600.3584", dir:"\system32", bulletin:bulletin, kb:kb)  ||
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"wkssvc.dll", version:"5.1.2600.5826", dir:"\system32", bulletin:bulletin, kb:kb)  ||
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"wkssvc.dll", version:"5.2.3790.4530", dir:"\system32", bulletin:bulletin, kb:kb)  ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"wkssvc.dll", version:"6.0.6000.16868", dir:"\system32", bulletin:bulletin, kb:kb)  ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"wkssvc.dll", version:"6.0.6000.21065", min_version:"6.0.6000.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"wkssvc.dll", version:"6.0.6001.18270", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"wkssvc.dll", version:"6.0.6001.22447", min_version:"6.0.6001.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"wkssvc.dll", version:"6.0.6002.18049", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"wkssvc.dll", version:"6.0.6002.22150", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:kb)
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
