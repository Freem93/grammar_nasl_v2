#
# (C) Tenable Network Security, Inc.
#

# Also supercedes MS02-005, MS02-047, MS02-027, MS02-023, MS02-015, MS01-015


include("compat.inc");

if (description)
{
 script_id(10861);
 script_version("$Revision: 1.105 $");
 script_cvs_date("$Date: 2017/05/26 15:15:34 $");

 script_cve_id("CVE-2002-0057");
 script_bugtraq_id(3699);
 script_osvdb_id(3032);
 script_xref(name:"CERT", value:"328163");
 script_xref(name:"MSFT", value:"MS02-005");
 script_xref(name:"MSFT", value:"MS05-020");
 script_xref(name:"MSKB", value:"316056");

 script_name(english:"MS02-005: MSIE 5.01 5.5 6.0 Cumulative Patch (890923)");
 script_summary(english:"Determines whether the hotfix 890923 is installed");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
client.");
 script_set_attribute(attribute:"description", value:
"The Cumulative Patch for IE is not applied on the remote host.

Impact of vulnerability : Run code of attacker's choice.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms02-005");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms02-020");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for the Windows 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/12/15");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/02/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/02/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
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

bulletin = 'MS02-005';
kb = '316056';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'2,5', xp:'1,2', win2003:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"5.2", sp:0, file:"Mshtml.dll", version:"6.0.3790.279", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:1, file:"Mshtml.dll", version:"6.0.2800.1498", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Mshtml.dll", version:"6.0.2900.2627", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", file:"Mshtml.dll", version:"6.0.2800.1498", min_version:"6.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", sp:3, file:"Mshtml.dll", version:"5.0.3539.2400", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", sp:4, file:"Mshtml.dll", version:"5.0.3826.2400", dir:"\system32", bulletin:bulletin, kb:kb)
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


