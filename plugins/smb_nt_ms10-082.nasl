#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(49959);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2015/06/14 04:36:30 $");

  script_cve_id("CVE-2010-2745");
  script_bugtraq_id(43772);
  script_osvdb_id(68557);
  script_xref(name:"MSFT", value:"MS10-082");

  script_name(english:"MS10-082: Vulnerability in Windows Media Player Could Allow Remote Code Execution (2378111)");
  script_summary(english:"Checks version of Wmp.dll / Wmploc.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has a media player that is affected by a code
execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Windows Media Player installed on the remote host has
a code execution vulnerability.  Objects are not deallocated properly
during a reload operation via a web browser.

A remote attacker could exploit this by tricking a user into visiting
a maliciously crafted web page."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-082");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows Media Player on
Windows 2003, XP, Vista, 2008, 7, and 2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

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

bulletin = 'MS10-082';
kbs = make_list("2378111");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'1,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

kb = "2378111";
if (
  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", file:"Wmp.dll", version:"12.0.7600.20792", min_version:"12.0.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", file:"Wmp.dll", version:"12.0.7600.16667", min_version:"12.0.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Wmploc.dll", version:"11.0.6002.22486", min_version:"11.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Wmploc.dll", version:"11.0.6002.18311", min_version:"11.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Wmploc.dll", version:"11.0.6001.7118", min_version:"11.0.6001.7100", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Wmploc.dll", version:"11.0.6001.7010", min_version:"11.0.6001.7000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003 / XP x64
  hotfix_is_vulnerable(os:"5.2", arch:"x64", sp:2, file:"Wmp.dll", version:"10.0.0.4008",  min_version:"10.0.0.0", dir:"\SysWOW64") ||
  hotfix_is_vulnerable(os:"5.2", arch:"x86", sp:2, file:"Wmp.dll", version:"10.0.0.4008",  min_version:"10.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # WMP 9 - 11 on XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Wmp.dll", version:"11.0.5721.5280", min_version:"11.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Wmp.dll", version:"10.0.0.4081", min_version:"10.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Wmp.dll", version:"9.0.0.4510", min_version:"9.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:'SMB/Missing/MS10-082', value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
