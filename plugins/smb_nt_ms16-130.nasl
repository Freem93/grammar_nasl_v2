#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94631);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/24 14:05:10 $");

  script_cve_id("CVE-2016-7212", "CVE-2016-7221", "CVE-2016-7222");
  script_bugtraq_id(94021, 94023, 94027);
  script_osvdb_id(146909, 146910, 146920);
  script_xref(name:"MSFT", value:"MS16-130");
  script_xref(name:"IAVA", value:"2016-A-0321");

  script_name(english:"MS16-130: Security Update for Microsoft Windows (3199172)");
  script_summary(english:"Checks the version of input.dll and oleaut32.dll, or the November 2016 Rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update or security
rollup. It is, therefore, affected by the following vulnerabilities :

  - A remote code execution vulnerability exists in the
    Windows image file handling functionality due to
    improper handling of image files. An unauthenticated,
    remote attacker can exploit this vulnerability by
    convincing a user to open a specially crafted image file
    from a web page or email message, resulting in the
    execution of arbitrary code in the context of the
    current user. (CVE-2016-7212)

  - An elevation of privilege vulnerability exists in
    Windows Input Method Editor (IME) due to improper
    loading of DLL files. A local attacker can exploit this,
    via a specially crafted application, to elevate
    privileges. (CVE-2016-7221)

  - An elevation of privilege vulnerability exists in
    Windows Task Scheduler due to improper handling of UNC
    paths. An authenticated, remote attacker can exploit
    this vulnerability by scheduling a new task with a
    specially crafted UNC path, resulting in the execution
    of arbitrary code with elevated system privileges.
    (CVE-2016-7222)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/security/MS16-130");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, 10, and 2016.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/08");

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

bulletin = 'MS16-130';
kbs = make_list(
  '3193418',
  '3196718',
  '3197867',
  '3197868',
  '3197873',
  '3197874',
  '3197876',
  '3197877',
  '3198585',
  '3198586',
  '3200970'
);

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

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
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"oleaut32.dll", version:"6.0.6002.24024", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3196718") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"oleaut32.dll", version:"6.0.6002.19700", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3196718") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"input.dll", version:"6.0.6002.24028", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3193418") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"input.dll", version:"6.0.6002.19705", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3193418") ||

  # Windows 7 / Server 2008 R2
  smb_check_rollup(os:"6.1", sp:1, rollup_date:"11_2016", bulletin:bulletin, rollup_kb_list:make_list(3197867, 3197868)) ||
  # Windows Server 2012
  smb_check_rollup(os:"6.2", sp:0, rollup_date:"11_2016", bulletin:bulletin, rollup_kb_list:make_list(3197876, 3197877)) ||
  # Windows 8.1 / Windows Server 2012 R2
  smb_check_rollup(os:"6.3", sp:0, rollup_date:"11_2016", bulletin:bulletin, rollup_kb_list:make_list(3197873, 3197874)) ||
  # Windows 10
  smb_check_rollup(os:"10", sp:0, os_build:"10240", rollup_date:"11_2016", bulletin:bulletin, rollup_kb_list:make_list(3198585)) ||
  smb_check_rollup(os:"10", sp:0, os_build:"10586", rollup_date:"11_2016", bulletin:bulletin, rollup_kb_list:make_list(3198586)) ||
  smb_check_rollup(os:"10", sp:0, os_build:"14393", rollup_date:"11_2016", bulletin:bulletin, rollup_kb_list:make_list(3200970))
)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}
