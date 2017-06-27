#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11147);
 script_version("$Revision: 1.40 $");
 script_cvs_date("$Date: 2017/05/26 15:15:35 $");

 script_cve_id("CVE-2002-0693", "CVE-2002-0694");
 script_bugtraq_id(4387, 5872, 5874);
 script_osvdb_id(867, 2992);
 script_xref(name:"MSFT", value:"MS02-055");
 script_xref(name:"MSKB", value:"323255");

 script_name(english:"MS02-055: Unchecked Buffer in Windows Help Facility Could Enable Code Execution (323255)");
 script_summary(english:"Checks for MS Hotfix Q323255, Unchecked Buffer in Windows Help facility");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
client.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the HTML Helpfacility ActiveX
control module that could allow an attacker to execute arbitrary code on
the remote host by constructing a malicious web page and enticing a
victim to visit it.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms02-055");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows NT, 2000 and XP.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/10/02");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/10/02");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/10/24");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2017 Tenable Network Security, Inc.");
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

bulletin = 'MS02-055';
kb = '323255';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(nt:'6', win2k:'1,3', xp:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"5.1", file:"Hhctrl.ocx", version:"5.2.3669.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", file:"Hhctrl.ocx", version:"5.2.3669.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"4.0", file:"Hhctrl.ocx", version:"5.2.3669.0", dir:"\system32", bulletin:bulletin, kb:kb)
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


