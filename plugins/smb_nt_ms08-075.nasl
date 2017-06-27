#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(35074);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2015/04/23 21:11:57 $");

 script_cve_id("CVE-2008-4268", "CVE-2008-4269");
 script_bugtraq_id(32651, 32652);
 script_osvdb_id(50565, 50566);
 script_xref(name:"MSFT", value:"MS08-075");
 script_xref(name:"IAVB", value:"2008-B-0083");

 script_name(english:"MS08-075: Vulnerabilities in Windows Search Could Allow Remote Code Execution (959349)");
 script_summary(english:"Determines the presence of update 959349");

 script_set_attribute(attribute:"synopsis", value:
"Vulnerabilities in the Windows Shell may allow an attacker to execute
privileged commands on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a version of the Windows Shell
that contains a vulnerability in the way it handles saved seaches.

An attacker might use this flaw to trick an administrator to execute a saved
search and therefore execute arbitrary commands on his behalf.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms08-075");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows Vista and 2008.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(399);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/12/09");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/12/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/10");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"stig_severity", value:"II");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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

bulletin = 'MS08-075';
kb = '958624';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Explorer.exe", version:"6.0.6000.16771", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Explorer.exe", version:"6.0.6000.20947", min_version:"6.0.6000.20000", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Explorer.exe", version:"6.0.6001.18164", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Explorer.exe", version:"6.0.6001.22298", min_version:"6.0.6001.22000", bulletin:bulletin, kb:kb)
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
