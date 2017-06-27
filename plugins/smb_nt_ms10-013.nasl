#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44423);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2015/04/23 21:11:58 $");

  script_cve_id("CVE-2010-0250");
  script_bugtraq_id(38112);
  script_osvdb_id(62257);
  script_xref(name:"MSFT", value:"MS10-013");
  script_xref(name:"IAVA", value:"2010-A-0025");

  script_name(english:"MS10-013: Vulnerability in Microsoft DirectShow Could Allow Remote Code Execution (977935)");
  script_summary(english:"Checks versions of Avifil32.dll and Quartz.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"It is possible to execute arbitrary code on the remote Windows host
using DirectShow."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Microsoft DirectShow installed on the remote host is
affected by a heap-based buffer overflow that can be triggered when
parsing AVI media files.

If an attacker can trick a user on the affected host into opening a
specially crafted AVI file, this issue could be leveraged to execute
arbitrary code subject to the user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-013");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista, 2008, 7, and 2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/09");

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

bulletin = 'MS10-013';
kbs = make_list("975560", "977914");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'2', vista:'0,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

if (!get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/DirectX/Version")) audit(AUDIT_NOT_INST, "DirectX");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1",                   file:"Quartz.dll",   version:"6.6.7600.20600", min_version:"6.6.7600.20000", dir:"\System32", bulletin:bulletin, kb:"975560") ||
  hotfix_is_vulnerable(os:"6.1",                   file:"Quartz.dll",   version:"6.6.7600.16490", min_version:"6.6.7600.16000", dir:"\System32", bulletin:bulletin, kb:"975560") ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Quartz.dll",   version:"6.6.6002.22295", min_version:"6.6.6002.22000", dir:"\System32", bulletin:bulletin, kb:"975560") ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Quartz.dll",   version:"6.6.6002.18158", min_version:"6.6.6002.18000", dir:"\System32", bulletin:bulletin, kb:"975560") ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Quartz.dll",   version:"6.6.6001.22590", min_version:"6.6.6001.22000", dir:"\System32", bulletin:bulletin, kb:"975560") ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Quartz.dll",   version:"6.6.6001.18389", min_version:"6.6.6001.18000", dir:"\System32", bulletin:bulletin, kb:"975560") ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"Quartz.dll",   version:"6.6.6000.21188", min_version:"6.6.6000.20000", dir:"\System32", bulletin:bulletin, kb:"975560") ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"Quartz.dll",   version:"6.6.6000.16986", min_version:"6.6.6000.16000", dir:"\System32", bulletin:bulletin, kb:"975560") ||

  # Windows 2003 / XP 64
  #
  # - AVI filter
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Avifil32.dll", version:"5.2.3790.4625",                                dir:"\System32", bulletin:bulletin, kb:"977914") ||
  # - Quartz
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Quartz.dll",   version:"6.5.3790.4625",                                dir:"\System32", bulletin:bulletin, kb:"975560") ||

  # Windows XP
  #
  # - AVI filter
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Avifil32.dll", version:"5.1.2600.5908",                                dir:"\System32", bulletin:bulletin, kb:"977914") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Avifil32.dll", version:"5.1.2600.3649",                                dir:"\System32", bulletin:bulletin, kb:"977914") ||
  # - Quartz
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Quartz.dll",   version:"6.5.2600.5908",                                dir:"\System32", bulletin:bulletin, kb:"975560") ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Quartz.dll",   version:"6.5.2600.3649",                                dir:"\System32", bulletin:bulletin, kb:"975560") ||

  # Windows 2000
  #
  # - AVI filter
  hotfix_is_vulnerable(os:"5.0",                   file:"Avifil32.dll", version:"5.0.2195.7359",                                dir:"\System32", bulletin:bulletin, kb:"977914") ||
  # - Quartz
  hotfix_is_vulnerable(os:"5.0",                   file:"Quartz.dll",   version:"6.5.1.913",     min_version:"6.5.0.0",         dir:"\System32", bulletin:bulletin, kb:"975560") ||
  # - Quartz in DirectX 9.0
  hotfix_is_vulnerable(os:"5.0",                   file:"Quartz.dll",   version:"6.1.9.738",                                    dir:"\System32", bulletin:bulletin, kb:"975560")
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
