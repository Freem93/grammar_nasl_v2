#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49951);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/05/06 17:11:38 $");

  script_cve_id("CVE-2010-3227");
  script_bugtraq_id(41333);
  script_osvdb_id(68585);
  script_xref(name:"IAVB", value:"2010-B-0091");
  script_xref(name:"MSFT", value:"MS10-074");

  script_name(english:"MS10-074: Vulnerability in Microsoft Foundation Classes Could Allow Remote Code Execution (2387149)");
  script_summary(english:"Checks the version of Mfc40u.dll / Mfc42u.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"It is possible to execute arbitrary code on the remote Windows host
through the Microsoft Foundation Class (MFC) Library component."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Microsoft Foundation Class (MFC) library component installed on
the remote host is affected by a stack-based buffer overflow in the
'UpdateFrameTitleForDocument()' function of the 'CFrameWnd' class.

If there is an application on the affected host built with the
affected MFC library that uses user-supplied data to set the
window title, it may be possible for an attacker to execute arbitrary
code on the remote host subject to the privileges of the user running
that application.

Note that an exploit involving PowerZip has been published."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-074");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS10-074';
kbs = make_list("2387149");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'1,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

kb = "2387149";
if (
  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1",       arch:"x64", file:"Mfc40u.dll", version:"4.1.0.6151", dir:"\SysWOW64", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"6.1",                   file:"Mfc40u.dll", version:"4.1.0.6151", dir:"\System32", bulletin:bulletin, kb:kb) ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, arch:"x64", file:"Mfc40u.dll", version:"4.1.0.6151", dir:"\SysWOW64", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, arch:"x64", file:"Mfc40u.dll", version:"4.1.0.6151", dir:"\SysWOW64", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Mfc40u.dll", version:"4.1.0.6151", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Mfc40u.dll", version:"4.1.0.6151", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003 / XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"Mfc40u.dll", version:"4.1.0.6151", dir:"\SysWOW64", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Mfc40u.dll", version:"4.1.0.6151", dir:"\System32", bulletin:bulletin, kb:kb) ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Mfc42u.dll", version:"6.2.8073.0", dir:"\System32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Mfc40u.dll", version:"4.1.0.6151", dir:"\System32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/MS10-074", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
