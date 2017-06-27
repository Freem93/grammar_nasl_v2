#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25885);
 script_version("$Revision: 1.30 $");
 script_cvs_date("$Date: 2016/12/09 20:54:59 $");

 script_cve_id("CVE-2007-3037", "CVE-2007-3035");
 script_bugtraq_id(25305, 25307);
 script_osvdb_id(36385, 36386);
 script_xref(name:"MSFT", value:"MS07-047");

 script_name(english:"MS07-047: Vulnerability in Windows Media Player Could Allow Remote Code Execution (936782)");
 script_summary(english:"Checks the version of Media Player");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Windows Media
Player.");
 script_set_attribute(attribute:"description", value:
"There is a vulnerability in the remote version of Windows Media Player
that may allow an attacker to execute arbitrary code on the remote host.

To exploit this flaw, one attacker would need to set up a rogue PNG
image and send it to a victim on the remote host.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS07-047");
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-07-047/");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003 and
Vista.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(94, 119);

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/08/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/14");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:windows_media_player");
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
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS07-047';
kb = '936782';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'1,2', vista:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

version = get_kb_item("SMB/WindowsMediaPlayer");
if (!version) audit(AUDIT_NOT_INST, "Windows Media Player");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"6.0", file:"Wmp.dll", version:"11.0.6000.6336", min_version:"11.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.2", sp:1, file:"Wmp.dll", version:"10.0.0.3709", min_version:"10.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Wmp.dll", version:"10.0.0.3998", min_version:"10.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.1", file:"Wmp.dll", version:"9.0.0.3354", min_version:"9.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", file:"Wmp.dll", version:"10.0.0.4058", min_version:"10.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", file:"Wmp.dll", version:"11.0.5721.5230", min_version:"11.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.0", file:"Wmpui.dll", version:"7.10.0.3080", min_version:"7.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", file:"Wmp.dll", version:"9.0.0.3354", min_version:"9.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb)
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
