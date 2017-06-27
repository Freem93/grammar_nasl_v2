#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94636);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/05/24 14:05:10 $");

  script_cve_id(
    "CVE-2016-7214",
    "CVE-2016-7215",
    "CVE-2016-7218",
    "CVE-2016-7246",
    "CVE-2016-7255"
  );
  script_bugtraq_id(
    93991,
    94000,
    94004,
    94063,
    94064
  );
  script_osvdb_id(
    146898, 
    146894,
    146897,
    146895,
    146896
  );
  script_xref(name:"MSFT", value:"MS16-135");
  script_xref(name:"IAVA", value:"2016-A-0322");

  script_name(english:"MS16-135: Security Update for Windows Kernel-Mode Drivers (3199135)");
  script_summary(english:"Checks the version of ntoskrnl.exe or the installed rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists in the
    Windows kernel that allows a local attacker, via a
    specially crafted application, to bypass the Address
    Space Layout Randomization (ASLR) feature and retrieve
    the memory address of a kernel object. (CVE-2016-7214)

  - Multiple elevation of privilege vulnerabilities exist in
    the Windows kernel-mode driver due to improper handling
    of objects in memory. A local attacker can exploit
    these, via a specially crafted application, to execute
    arbitrary code in kernel mode. (CVE-2016-7215,
    CVE-2016-7246, CVE-2016-7255)

  - An information disclosure vulnerability exists in the
    bowser.sys kernel-mode driver due to improper handling
    objects in memory. A local attacker can exploit this,
    via a specially crafted application, to disclose
    sensitive information. (CVE-2016-7218)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-135");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, 10, and 2016.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

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

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "smb_check_rollup.nasl");
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

bulletin = 'MS16-135';
kbs = make_list(
  '3198234',
  '3194371',
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

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# Windows 8 EOL
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32k.sys", version:"6.0.6002.24029", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3198234") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32k.sys", version:"6.0.6002.19706", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3198234") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"bowser.sys", version:"6.0.6002.24021", min_version:"6.0.6002.23000", dir:"\system32\drivers", bulletin:bulletin, kb:"3194371") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"bowser.sys", version:"6.0.6002.19698", min_version:"6.0.6002.18000", dir:"\system32\drivers", bulletin:bulletin, kb:"3194371") ||
  # 8.1 / 2012 R2
  smb_check_rollup(os:"6.3",
                   sp:0,
                   rollup_date: "11_2016",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(3197873, 3197874)) ||
  # 2012
  smb_check_rollup(os:"6.2",
                   sp:0,
                   rollup_date: "11_2016",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(3197876, 3197877)) ||
  # 7 / 2008 R2
  smb_check_rollup(os:"6.1",
                   sp:1,
                   rollup_date: "11_2016",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(3197867, 3197868)) ||
  # 10 (1507)
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"10240",
                   rollup_date: "11_2016",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(3198585)) ||
  # 10 (1511)
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"10586",
                   rollup_date: "11_2016",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(3198586)) ||
  # 10 (1607)
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"14393",
                   rollup_date: "11_2016",
                   bulletin:bulletin,
                   rollup_kb_list:make_list(3200970))
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
