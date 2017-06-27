#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97741);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/26 23:57:36 $");

  script_cve_id("CVE-2017-0055");
  script_bugtraq_id(96622);
  script_osvdb_id(153722);
  script_xref(name:"MSFT", value:"MS17-016");
  script_xref(name:"MSKB", value:"4012373");
  script_xref(name:"MSKB", value:"4012212");
  script_xref(name:"MSKB", value:"4012215");
  script_xref(name:"MSKB", value:"4012213");
  script_xref(name:"MSKB", value:"4012216");
  script_xref(name:"MSKB", value:"4012214");
  script_xref(name:"MSKB", value:"4012217");
  script_xref(name:"MSKB", value:"4012606");
  script_xref(name:"MSKB", value:"4013198");
  script_xref(name:"MSKB", value:"4013429");
  script_xref(name:"IAVB", value:"2017-B-0033");

  script_name(english:"MS17-016: Security Update for Windows IIS (4013074)");
  script_summary(english:"Checks the file version of iiscore.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a cross-site scripting
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by a cross-site scripting (XSS) vulnerability due
to improper validation of user-supplied input. An unauthenticated,
remote attacker can exploit this, via a specially crafted request, to
execute arbitrary script code in a user's browser session.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS17-016");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, 10, and 2016.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

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

bulletin = 'MS17-016';
kbs = make_list(
  "4012373", # Windows Vista / 2008
  "4012212", # Windows 7 / 2008 R2 Security Only
  "4012215", # Windows 7 / 2008 R2 Monthly Rollup
  "4012213", # Windows 8.1 / 2012 R2 Security Only
  "4012216", # Windows 8.1 / 2012 R2 / RT 8.1 Monthly Rollup
  "4012214", # Windows 2012 Security Only
  "4012217", # Windows 2012 Monthly Rollup
  "4012606", # Windows 10 RTM
  "4013198", # Windows 10 1511
  "4013429"  # Windows 10 1607
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if ("Windows 8" >< productname && "8.1" >!< productname)
  audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  #  "3200970", # Windows 10 1607
  smb_check_rollup(os:"10", sp:0, os_build:"14393", rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4013429)) ||

  #  "3198586", # Windows 10 1511
  smb_check_rollup(os:"10", sp:0, os_build:"10586", rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4013198)) ||

  #  "3198585", # Windows 10 RTM
  smb_check_rollup(os:"10", sp:0, os_build:"10240", rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4012606)) ||

  #  "4012213", # Windows 8.1 / 2012 R2 Security Only
  #  "4012216", # Windows 8.1 / 2012 R2 / RT 8.1 Monthly Rollup
  smb_check_rollup(os:"6.3", sp:0, rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4012213, 4012216)) ||

  #  "4012214", # Windows 2012 Security Only
  #  "4012217", # Windows 2012 Monthly Rollup
  smb_check_rollup(os:"6.2", sp:0, rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4012214, 4012217)) ||

  #  "4012212", # Windows 7 / 2008 R2 Security Only
  #  "4012215", # Windows 7 / 2008 R2 Monthly Rollup
  smb_check_rollup(os:"6.1", sp:1, rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4012212, 4012215)) ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"gdi32.dll", version:"6.0.6002.19743", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"4012373") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"custerr.dll", version:"7.0.6002.19741", min_version:"7.0.6002.18000", dir:"\system32\inetsrv", bulletin:bulletin, kb:"4012373") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"custerr.dll", version:"7.0.6002.24065", min_version:"7.0.6002.21000", dir:"\system32\inetsrv", bulletin:bulletin, kb:"4012373")
)
{
  set_kb_item(name:'www/0/XSS', value:TRUE); # CVE-2017-0055
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}
