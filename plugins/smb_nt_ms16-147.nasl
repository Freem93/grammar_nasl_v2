#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95766);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/05/24 14:05:10 $");

  script_cve_id("CVE-2016-7274");
  script_bugtraq_id(94758);
  script_osvdb_id(148616);
  script_xref(name:"MSFT", value:"MS16-147");
  script_xref(name:"IAVA", value:"2016-A-0352");

  script_name(english:"MS16-147: Security Update for Microsoft Uniscribe (3204063)");
  script_summary(english:"Checks the version of usp10.dll or the installed rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by a remote code execution vulnerability in
Windows Uniscribe due to improper handling of objects in memory. An
unauthenticated, remote attacker can exploit this vulnerability by
convincing a user to visit a specially crafted website or open a
specially crafted document, resulting in the execution of arbitrary
code in the context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-147");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, 10, and 2016.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "smb_check_rollup.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS16-147';
kbs = make_list(
  "3196348", # Windows Vista / 2008
  "3205394", # Windows 7 / 2008 R2 Security Only
  "3207752", # Windows 7 / 2008 R2 Monthly Rollup
  "3205400", # Windows 8.1 / 2012 R2 Security Only
  "3205401", # Windows 8.1 / 2012 R2 / RT 8.1 Monthly Rollup
  "3205408", # Windows 2012 Security Only
  "3205409", # Windows 2012 Monthly Rollup
  "3205383", # Windows 10 RTM
  "3205386", # Windows 10 1511
  "3206632"  # Windows 10 1607 / 2016
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname)
  audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  #  "3206632", # Windows 10 1607 / 2016
  smb_check_rollup(os:"10", sp:0, os_build:"14393", rollup_date:"12_2016", bulletin:bulletin, rollup_kb_list:make_list(3206632)) ||

  #  "3205386", # Windows 10 1511
  smb_check_rollup(os:"10", sp:0, os_build:"10586", rollup_date:"12_2016", bulletin:bulletin, rollup_kb_list:make_list(3205386)) ||

  #  "3205383", # Windows 10 RTM
  smb_check_rollup(os:"10", sp:0, os_build:"10240", rollup_date:"12_2016", bulletin:bulletin, rollup_kb_list:make_list(3205383)) ||

  #  "3205400", # Windows 8.1 / 2012 R2 Security Only
  #  "3205401", # Windows 8.1 / 2012 R2 / RT 8.1 Monthly Rollup
  smb_check_rollup(os:"6.3", sp:0, rollup_date:"12_2016", bulletin:bulletin, rollup_kb_list:make_list(3205400, 3205401)) ||

  #  "3205408", # Windows 2012 Security Only
  #  "3205409", # Windows 2012 Monthly Rollup
  smb_check_rollup(os:"6.2", sp:0, rollup_date:"12_2016", bulletin:bulletin, rollup_kb_list:make_list(3205408, 3205409)) ||

  #  "3205394", # Windows 7 / 2008 R2 Security Only
  #  "3207752", # Windows 7 / 2008 R2 Monthly Rollup
  smb_check_rollup(os:"6.1", sp:1, rollup_date:"12_2016", bulletin:bulletin, rollup_kb_list:make_list(3205394, 3207752)) ||

  #  "3196348", # Windows Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"usp10.dll", version:"1.626.6002.24030", min_version:"1.626.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3196348")||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"usp10.dll", version:"1.626.6002.19707", min_version:"1.626.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3196348")
)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}
