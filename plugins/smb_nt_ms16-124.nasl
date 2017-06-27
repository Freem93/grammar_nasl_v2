#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94013);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/24 14:05:10 $");

  script_cve_id(
    "CVE-2016-0070",
    "CVE-2016-0073",
    "CVE-2016-0075",
    "CVE-2016-0079"
  );
  script_bugtraq_id(
    93354,
    93355,
    93356,
    93357
  );
  script_osvdb_id(
    145403,
    145404,
    145405,
    145406
  );
  script_xref(name:"MSFT", value:"MS16-124");
  script_xref(name:"IAVA", value:"2016-A-0282");

  script_name(english:"MS16-124: Security Update for Windows Registry (3193227)");
  script_summary(english:"Checks the version of ntoskrnl.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple information disclosure
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple information disclosure vulnerabilities
in the kernel API that allow a local attacker, via a specially crafted
application, to disclose sensitive registry information.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/security/MS16-124");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS16-124';
kbs = make_list(
  '3185330',
  '3185331',
  '3185332',
  '3191256',
  '3192391',
  '3192392',
  '3192393',
  '3192440',
  '3192441',
  '3194798'
);

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_NOTE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0',  win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname)
 audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"ntoskrnl.exe", version:"6.0.6002.24020", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3191256") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"ntoskrnl.exe", version:"6.0.6002.19697", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3191256") ||
  # Windows 7 / Server 2008 R2
  smb_check_rollup(os:"6.1", sp:1, rollup_date:"10_2016", bulletin:bulletin, rollup_kb_list:make_list(3185330, 3192391)) ||
  # Windows Server 2012
  smb_check_rollup(os:"6.2", sp:0, rollup_date:"10_2016", bulletin:bulletin, rollup_kb_list:make_list(3185332, 3192393)) ||
  # Windows 8.1 / Windows Server 2012 R2
  smb_check_rollup(os:"6.3", sp:0, rollup_date:"10_2016", bulletin:bulletin, rollup_kb_list:make_list(3185331, 3192392)) ||
  # Windows 10
  smb_check_rollup(os:"10", sp:0, os_build:"10240", rollup_date:"10_2016", bulletin:bulletin, rollup_kb_list:make_list(3192440)) ||
  smb_check_rollup(os:"10", sp:0, os_build:"10586", rollup_date:"10_2016", bulletin:bulletin, rollup_kb_list:make_list(3192441)) ||
  smb_check_rollup(os:"10", sp:0, os_build:"14393", rollup_date:"10_2016", bulletin:bulletin, rollup_kb_list:make_list(3194798))
)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_note();
  hotfix_check_fversion_end();
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}
