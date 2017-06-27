#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94635);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/24 14:05:10 $");

  script_cve_id(
    "CVE-2016-0026",
    "CVE-2016-3332",
    "CVE-2016-3333",
    "CVE-2016-3334",
    "CVE-2016-3335",
    "CVE-2016-3338",
    "CVE-2016-3340",
    "CVE-2016-3342",
    "CVE-2016-3343",
    "CVE-2016-7184"
  );
  script_bugtraq_id(
    93998,
    94007,
    94008,
    94009,
    94010,
    94011,
    94012,
    94013,
    94014,
    94015
  );
  script_osvdb_id(
    146884,
    146885,
    146886,
    146887,
    146888,
    146889,
    146890,
    146891,
    146892,
    146893
  );
  script_xref(name:"MSFT", value:"MS16-134");

  script_name(english:"MS16-134: Security Update for Common Log File System Driver (3193706)");
  script_summary(english:"Checks the version of clfs.sys");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple elevation of privilege
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple elevation of privilege vulnerabilities
in the Windows Common Log File System (CLFS) driver due to improper
handling of objects in memory. A local attacker can exploit this, via
a specially crafted application, to gain elevated privileges.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/security/MS16-134");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, 10, and 2016.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
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

bulletin = 'MS16-134';
kbs = make_list(
  "3181707",
  "3197873",
  "3197874",
  "3197876",
  "3197877",
  "3197867",
  "3197868",
  "3198585",
  "3200970",
  "3198586"
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
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"clfs.sys", version:"6.0.6002.24026", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3181707") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"clfs.sys", version:"6.0.6002.19703", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3181707") ||
  # Windows 7 / Server 2008 R2
  smb_check_rollup(os:"6.1", sp:1, rollup_date:"11_2016", bulletin:bulletin, rollup_kb_list:make_list(3197867, 3197868)) ||
  # Windows Server 2012
  smb_check_rollup(os:"6.2", sp:0, rollup_date:"11_2016", bulletin:bulletin, rollup_kb_list:make_list(3197876, 3197877)) ||
  # Windows 8.1 / Windows Server 2012 R2
  smb_check_rollup(os:"6.3", sp:0, rollup_date:"11_2016", bulletin:bulletin, rollup_kb_list:make_list(3197873, 3197874)) ||
  # Windows 10
  smb_check_rollup(os:"10", sp:0, os_build:"10240", rollup_date:"11_2016", bulletin:bulletin, rollup_kb_list:make_list(3198585)) ||
  # Windows 10 1511
  smb_check_rollup(os:"10", sp:0, os_build:"10586", rollup_date:"11_2016", bulletin:bulletin, rollup_kb_list:make_list(3198586)) ||
  # Windows 10 1607
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
