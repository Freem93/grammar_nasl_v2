#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(51170);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2015/04/23 21:35:40 $");

  script_cve_id(
    "CVE-2010-3939",
    "CVE-2010-3940",
    "CVE-2010-3941",
    "CVE-2010-3942",
    "CVE-2010-3943",
    "CVE-2010-3944"
  );
  script_bugtraq_id(42291, 45286, 45287, 45288, 45289, 45298);
  script_osvdb_id(69797, 69798, 69799, 69800, 69801, 69802);
  script_xref(name:"MSFT", value:"MS10-098");

  script_name(english:"MS10-098: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (2436673)");
  script_summary(english:"Checks version of Win32k.sys");

  script_set_attribute(attribute:"synopsis", value:
"A privilege escalation vulnerability exists in the Windows kernel.");

  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows that contains a flaw
in the kernel that may lead to a privilege escalation by running a
specially crafted application.

To exploit this vulnerability an attacker must have valid logon
credentials and be able to log on locally.");

  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-098");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for XP, 2003, Vista, 2008, 7,
and 2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/15");

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
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS10-098';
kbs = make_list("2436673");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'1,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

kb = "2436673";
if (
  # Windows 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Win32k.sys", version:"6.1.7600.20821", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Win32k.sys", version:"6.1.7600.16691", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Win32k.sys", version:"6.0.6002.22506", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Win32k.sys", version:"6.0.6002.18328", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Win32k.sys", version:"6.0.6001.22778", min_version:"6.0.6001.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Win32k.sys", version:"6.0.6001.18539", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003 / XP 64-bit
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Win32k.sys", version:"5.2.3790.4788", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP 32-bit
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Win32k.sys", version:"5.1.2600.6046", dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/MS10-098", value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
