#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25024);
 script_version("$Revision: 1.28 $");
 script_cvs_date("$Date: 2015/05/07 12:06:03 $");

 script_cve_id("CVE-2006-6696", "CVE-2006-6797", "CVE-2007-1209");
 script_bugtraq_id(21688, 23324, 23338);
 script_osvdb_id(31659, 31897, 34008);
 script_xref(name:"MSFT", value:"MS07-021");
 script_xref(name:"CERT", value:"740636");
 script_xref(name:"CERT", value:"219848");
 script_xref(name:"EDB-ID", value:"2967");

 script_name(english:"MS07-021: Vulnerabilities in CSRSS Could Allow Remote Code Execution (930178)");
 script_summary(english:"Determines the presence of update 930178");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
browser.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows containing a bug in the
CSRSS error message handling routine that could allow an attacker to
execute arbitrary code on the remote host by luring a user on the remote
host into visiting a rogue website.

Additionally, the system is prone to the following types of attack :

- Local Privilege Elevation

- Denial of Service (Local)");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS07-021");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003 and
Vista.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_cwe_id(119);

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/15");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/04/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/04/10");

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
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS07-021';
kb = "930178";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2', win2003:'0,2', vista:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Winsrv.dll", version:"6.0.6000.16445", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Winsrv.dll", version:"6.0.6000.20522", min_version:"6.0.6000.20000", dir:"\System32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Winsrv.dll", version:"5.2.3790.4043", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:1, file:"Winsrv.dll", version:"5.2.3790.2902", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:0, file:"Winsrv.dll", version:"5.2.3790.658", dir:"\System32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.1", file:"Winsrv.dll", version:"5.1.2600.3103", dir:"\System32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.0", file:"Winsrv.dll", version:"5.0.2195.7135", dir:"\System32", bulletin:bulletin, kb:kb)
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
