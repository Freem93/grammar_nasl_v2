#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45507);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2015/04/23 21:11:58 $");

  script_cve_id(
    "CVE-2009-3676",
    "CVE-2010-0269",
    "CVE-2010-0270",
    "CVE-2010-0476",
    "CVE-2010-0477"
  );
  script_bugtraq_id(36989, 39312, 39336, 39339, 39340);
  script_osvdb_id(59957, 64925, 64926, 64927, 64928);
  script_xref(name:"MSFT", value:"MS10-020");

  script_name(english:"MS10-020: Vulnerabilities in SMB Client Could Allow Remote Code Execution (980232)");
  script_summary(english:"Checks version of Mrxsmb.sys");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Arbitrary code can be executed on the remote host through the
installed SMB client."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of the SMB client software installed on the remote
Windows host may be affected by one or more vulnerabilities,
including some that could allow arbitrary code execution :

  - Incorrect handling of incomplete SMB responses could
    be abused to cause the system to stop responding.
    (CVE-2009-3676)

  - A vulnerability in the way the SMB client allocates
    memory when parsing specially crafted SMB responses
    could be abused by an unauthenticated, remote attacker
    to execute arbitrary code with system-level privileges.
    (CVE-2010-0269)

  - Improper validation of fields in SMB responses could
    lead to a memory corruption issue and in turn to
    arbitrary code execution with system-level privileges.
    (CVE-2010-0270)

  - Improper parsing of SMB transaction responses could
    lead to a memory corruption issue resulting in code
    execution with system-level privileges. (CVE-2010-0476)

  - Improper handling of SMB responses could cause the SMB
    client to consume the entire response and indicate an
    invalid value to the Winsock kernel, which in turn
    could allow remote code execution and result in the
    compromise of the affected system. (CVE-2010-0477)"
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-020");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista, 2008, 7, and 2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

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

bulletin = 'MS10-020';
kbs = make_list("980232");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'2', vista:'0,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

kb = "980232";

if (
  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1",                   file:"Mrxsmb.sys", version:"6.1.7600.20655", min_version:"6.1.7600.20000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1",                   file:"Mrxsmb.sys", version:"6.1.7600.16539", min_version:"6.1.7600.16000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Mrxsmb.sys", version:"6.0.6002.22346", min_version:"6.0.6002.22000", dir:"\System32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Mrxsmb.sys", version:"6.0.6002.18213", min_version:"6.0.6002.18000", dir:"\System32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Mrxsmb.sys", version:"6.0.6001.22641", min_version:"6.0.6001.22000", dir:"\System32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Mrxsmb.sys", version:"6.0.6001.18431", min_version:"6.0.6001.18000", dir:"\System32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"Mrxsmb.sys", version:"6.0.6000.21230", min_version:"6.0.6000.20000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"Mrxsmb.sys", version:"6.0.6000.17025", min_version:"6.0.6000.16000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Windows 2003 / XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Mrxsmb.sys", version:"5.2.3790.4671",                                dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Mrxsmb.sys", version:"5.1.2600.5944",                                dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Mrxsmb.sys", version:"5.1.2600.3675",                                dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0",                   file:"Mrxsmb.sys", version:"5.0.2195.7379",                                dir:"\system32\drivers", bulletin:bulletin, kb:kb)
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
