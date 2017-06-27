#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(43063);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id("CVE-2009-2505", "CVE-2009-3677");
  script_bugtraq_id(37197, 37198);
  script_osvdb_id(60832, 60833);
  script_xref(name:"IAVA", value:"2009-A-0126");
  script_xref(name:"MSFT", value:"MS09-071");

  script_name(english:"MS09-071: Vulnerabilities in Internet Authentication Service Could Allow Remote Code Execution (974318)");
  script_summary(english:"Checks the version of Rastls.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has multiple vulnerabilities in an
authentication service."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host has the following vulnerabilities in the
Internet Authentication Service :

  - There is a memory corruption vulnerability in the PEAP
    authentication implementation.  A remote, unauthenticated
    attacker could exploit this to execute arbitrary code as
    SYSTEM.  (CVE-2009-2505)

  - Sending a specially crafted MS-CHAP v2 authentication
    request could allow a remote attacker to obtain the
    privileges of a specific, authorized user. (CVE-2009-3677)"
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-071");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista, and 2008."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94, 255, 287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS09-071';
kb = '974318';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'2', vista:'0,2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0",   file:"Rastls.dll", version:"6.0.6000.16932", min_version:"6.0.6000.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",   file:"Rastls.dll", version:"6.0.6000.21134", min_version:"6.0.6000.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",   file:"Rastls.dll", version:"6.0.6001.18336", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",   file:"Rastls.dll", version:"6.0.6001.22536", min_version:"6.0.6001.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",   file:"Rastls.dll", version:"6.0.6002.18116", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",   file:"Rastls.dll", version:"6.0.6002.22240", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003 / XP SP2 x64
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Rastls.dll", version:"5.2.3790.4600", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Rastls.dll",  version:"5.1.2600.3632", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Rastls.dll",  version:"5.1.2600.5886", dir:"\system32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.0", file:"Rastls.dll",  version:"5.0.2195.7344", dir:"\system32", bulletin:bulletin, kb:kb)
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
