#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(49960);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2015/04/23 21:35:40 $");

  script_cve_id("CVE-2010-1263");
  script_bugtraq_id(40574);
  script_osvdb_id(65219);
  script_xref(name:"MSFT", value:"MS10-083");
  script_xref(name:"IAVA", value:"2010-A-0134");

  script_name(english:"MS10-083: Vulnerability in COM Validation in Windows Shell and WordPad Could Allow Remote Code Execution (2405882)");
  script_summary(english:"Checks version of Msshq.dll / Structuredquery.dll and Ole32.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote windows host is affected by a remote code execution
vulnerability.");

  script_set_attribute(attribute:"description", value:
"The remote windows host contains a version of the Windows Shell or
the WordPad text editor that contains a vulnerability in the way it
handles shortcut files.

An attacker, exploiting this flaw, can execute arbitrary commands on
the remote host subject to the privileges of the user opening the
file.");

  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-083");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

bulletin = 'MS10-083';
kbs = make_list("979687");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'1,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # WordPad
  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1",             file:"Ole32.dll", version:"6.1.7600.20744", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:"979687") ||
  hotfix_is_vulnerable(os:"6.1",             file:"Ole32.dll", version:"6.1.7600.16624", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:"979687") ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2,       file:"Ole32.dll", version:"6.0.6002.22433", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:"979687") ||
  hotfix_is_vulnerable(os:"6.0", sp:2,       file:"Ole32.dll", version:"6.0.6002.18277", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"979687") ||
  hotfix_is_vulnerable(os:"6.0", sp:1,       file:"Ole32.dll", version:"6.0.6001.22720", min_version:"6.0.6001.22000", dir:"\system32", bulletin:bulletin, kb:"979687") ||
  hotfix_is_vulnerable(os:"6.0", sp:1,       file:"Ole32.dll", version:"6.0.6001.18498", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:"979687") ||

  # Windows 2003 / XP x64
  hotfix_is_vulnerable(os:"5.2",             file:"Ole32.dll", version:"5.2.3790.4750", dir:"\system32", bulletin:bulletin, kb:"979687") ||

  # Windows XP
  hotfix_is_vulnerable(os:"5.1",             file:"Ole32.dll", version:"5.1.2600.6010", dir:"\system32", bulletin:bulletin, kb:"979687") ||

  # Windows Shell
  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", file:"StructuredQuery.dll", version:"7.0.7600.20707", min_version:"7.0.7600.20000", dir:"\system32", bulletin:bulletin, kb:"979688") ||
  hotfix_is_vulnerable(os:"6.1", file:"StructuredQuery.dll", version:"7.0.7600.16587", min_version:"7.0.7600.16000", dir:"\system32", bulletin:bulletin, kb:"979688") ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", file:"msshsq.dll",          version:"7.0.6002.22398", min_version:"7.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:"979688") ||
  hotfix_is_vulnerable(os:"6.0", file:"msshsq.dll",          version:"7.0.6002.18255", min_version:"7.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"979688") ||
  hotfix_is_vulnerable(os:"6.0", file:"msshsq.dll",          version:"6.0.6001.22685", min_version:"6.0.6001.22000", dir:"\system32", bulletin:bulletin, kb:"979688") ||
  hotfix_is_vulnerable(os:"6.0", file:"msshsq.dll",          version:"6.0.6001.18470", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:"979688")
  )
{
  set_kb_item(name:"SMB/Missing/MS10-083", value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
