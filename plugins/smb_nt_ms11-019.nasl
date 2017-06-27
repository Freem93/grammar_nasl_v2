#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(53376);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/05/07 12:06:04 $");

  script_cve_id("CVE-2011-0654", "CVE-2011-0660");
  script_bugtraq_id(46360, 47239);
  script_osvdb_id(71772, 71773);
  script_xref(name:"CERT", value:"323172");
  script_xref(name:"EDB-ID", value:"16166");
  script_xref(name:"MSFT", value:"MS11-019");

  script_name(english:"MS11-019: Vulnerabilities in SMB Client Could Allow Remote Code Execution (2511455)");
  script_summary(english:"Checks version of Mrxsmb.sys");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Arbitrary code can be executed on the remote host through the installed
SMB client."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of the SMB client software installed on the remote Windows
host may be affected by multiple vulnerabilities which could allow an
attacker to execute arbitrary code on the remote host subject to the
privileges of the user running the affected software.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-019");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/13");

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

bulletin = 'MS11-019';
kb = "2511455";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'1,2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1,             file:"Mrxsmb.sys", version:"6.1.7601.21666", min_version:"6.1.7601.20000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1,             file:"Mrxsmb.sys", version:"6.1.7601.17565", min_version:"6.1.7601.16000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0,             file:"Mrxsmb.sys", version:"6.1.7600.20907", min_version:"6.1.7600.20000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0,             file:"Mrxsmb.sys", version:"6.1.7600.16765", min_version:"6.1.7600.16000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, arch:"x64", file:"Mrxsmb.sys", version:"6.0.6002.22592", min_version:"6.0.6002.22000", dir:"\System32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, arch:"x64", file:"Mrxsmb.sys", version:"6.0.6002.18407", min_version:"6.0.6002.18000", dir:"\System32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, arch:"x64", file:"Mrxsmb.sys", version:"6.0.6001.22857", min_version:"6.0.6001.22000", dir:"\System32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, arch:"x64", file:"Mrxsmb.sys", version:"6.0.6001.18602", min_version:"6.0.6001.18000", dir:"\System32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, arch:"x86", file:"Mrxsmb.sys", version:"6.0.6002.22594", min_version:"6.0.6002.22000", dir:"\System32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, arch:"x86", file:"Mrxsmb.sys", version:"6.0.6002.18409", min_version:"6.0.6002.18000", dir:"\System32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, arch:"x86", file:"Mrxsmb.sys", version:"6.0.6001.22859", min_version:"6.0.6001.22000", dir:"\System32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, arch:"x86", file:"Mrxsmb.sys", version:"6.0.6001.18604", min_version:"6.0.6001.18000", dir:"\System32\drivers", bulletin:bulletin, kb:kb) ||

  # Windows 2003 / XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Mrxsmb.sys", version:"5.2.3790.4833",                                dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Mrxsmb.sys", version:"5.1.2600.6082",                                dir:"\system32\drivers", bulletin:bulletin, kb:kb)
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
