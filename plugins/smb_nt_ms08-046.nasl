#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(33875);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2015/04/23 21:11:57 $");

 script_cve_id("CVE-2008-2245");
 script_bugtraq_id(30594);
 script_osvdb_id(47395);
 script_xref(name:"CERT", value:"309739");
 script_xref(name:"IAVA", value:"2008-A-0060");
 script_xref(name:"MSFT", value:"MS08-046");

 script_name(english:"MS08-046: Vulnerability in Microsoft Windows Image Color Management System Could Allow Remote Code Execution (952954)");
 script_summary(english:"Determines the presence of update 952954");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the Microsoft
Color Management System (MSCMS) module of the Microsoft ICM
componenents.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Color Management Module that
is vulnerable to a security flaw which could allow an attacker to
execute arbitrary code on the remote host by crafting a malformed image
file and entice a victim to open it.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms08-046");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(119);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/08/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/08/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"stig_severity", value:"I");
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

bulletin = 'MS08-046';
kb = '952954';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'1,2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mscms.dll", version:"5.2.3790.4320", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:1, file:"Mscms.dll", version:"5.2.3790.3163", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Mscms.dll", version:"5.1.2600.5627", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Mscms.dll", version:"5.1.2600.3396", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0",       file:"Mscms.dll", version:"5.0.2195.7162", dir:"\system32", bulletin:bulletin, kb:kb)
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
