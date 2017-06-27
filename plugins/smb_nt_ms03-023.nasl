#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11878);
 script_version("$Revision: 1.38 $");
 script_cvs_date("$Date: 2017/05/25 13:29:27 $");

 script_cve_id("CVE-2003-0469");
 script_bugtraq_id(8016);
 script_osvdb_id(2963);
 script_xref(name:"MSFT", value:"MS03-023");
 script_xref(name:"CERT", value:"823260");
 script_xref(name:"MSKB", value:"823559");

 script_name(english:"MS03-023: Buffer Overrun In HTML Converter Could Allow Code Execution (823559)");
 script_summary(english:"Checks for hotfix Q823559");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
client.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the HTML Converter module that
could allow an attacker to execute arbitrary code on the remote host by
constructing a malicious web page and enticing a victim to visit this
web page.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms03-023");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows NT, 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/06/22");
 script_set_attribute(attribute:"patch_publication_date", value:"2003/07/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/10/13");

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

bulletin = 'MS03-023';
kb = "823559";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(nt:'6', win2k:'2,4', xp:'0,1', win2003:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

path = hotfix_get_commonfilesdir();
if (!path) exit(1, "Failed to get the Common Files directory.");

share = hotfix_path2share(path:path);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

path += "\Microsoft Shared\TextConv";

if (
  hotfix_is_vulnerable(os:"5.2", sp:0, file:"Msconv97.dll", version:"2003.1100.5426.0", path:path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:1, file:"Msconv97.dll", version:"2003.1100.5426.0", path:path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:0, file:"Msconv97.dll", version:"2003.1100.5426.0", path:path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0",       file:"Msconv97.dll", version:"2003.1100.5426.0", path:path, bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"4.0",       file:"Msconv97.dll", version:"2003.1100.5426.0", path:path, bulletin:bulletin, kb:kb)
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
