#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97732);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/26 23:57:36 $");

  script_cve_id(
    "CVE-2017-0072",
    "CVE-2017-0083",
    "CVE-2017-0084",
    "CVE-2017-0085",
    "CVE-2017-0086",
    "CVE-2017-0087",
    "CVE-2017-0088",
    "CVE-2017-0089",
    "CVE-2017-0090",
    "CVE-2017-0091",
    "CVE-2017-0092",
    "CVE-2017-0111",
    "CVE-2017-0112",
    "CVE-2017-0113",
    "CVE-2017-0114",
    "CVE-2017-0115",
    "CVE-2017-0116",
    "CVE-2017-0117",
    "CVE-2017-0118",
    "CVE-2017-0119",
    "CVE-2017-0120",
    "CVE-2017-0121",
    "CVE-2017-0122",
    "CVE-2017-0123",
    "CVE-2017-0124",
    "CVE-2017-0125",
    "CVE-2017-0126",
    "CVE-2017-0127",
    "CVE-2017-0128"
  );
  script_bugtraq_id(
    96599,
    96603,
    96604,
    96605,
    96606,
    96607,
    96608,
    96610,
    96652,
    96657,
    96658,
    96659,
    96660,
    96661,
    96663,
    96665,
    96666,
    96667,
    96668,
    96669,
    96670,
    96672,
    96673,
    96674,
    96675,
    96676,
    96678,
    96679,
    96680
  );
  script_osvdb_id(
    153680,
    153681,
    153682,
    153683,
    153684,
    153685,
    153686,
    153687,
    153688,
    153689,
    153690,
    153691,
    153692,
    153693,
    153694,
    153695,
    153696,
    153697,
    153698,
    153699,
    153700,
    153701,
    153702,
    153703,
    153704,
    153705,
    153706,
    153707,
    153708
  );
  script_xref(name:"MSFT", value:"MS17-011");
  script_xref(name:"MSKB", value:"4012212");
  script_xref(name:"MSKB", value:"4012213");
  script_xref(name:"MSKB", value:"4012214");
  script_xref(name:"MSKB", value:"4012215");
  script_xref(name:"MSKB", value:"4012216");
  script_xref(name:"MSKB", value:"4012217");
  script_xref(name:"MSKB", value:"4012583");
  script_xref(name:"MSKB", value:"4012606");
  script_xref(name:"MSKB", value:"4013198");
  script_xref(name:"MSKB", value:"4013429");
  script_xref(name:"IAVA", value:"2017-A-0066");

  script_name(english:"MS17-011: Security Update for Microsoft Uniscribe (4013076)");
  script_summary(english:"Checks the version of Gdi32.dll and for rollup patches applied.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple vulnerabilities :

    - Multiple remote code execution vulnerabilities exist
      in Windows Uniscribe due to improper handling of
      objects in memory. An unauthenticated, remote attacker
      can exploit these to execute arbitrary code by
      convincing a user to view a specially crafted website
      or open a specially crafted document file.
      (CVE-2017-0072, CVE-2017-0083, CVE-2017-0084,
      CVE-2017-0086, CVE-2017-0087, CVE-2017-0088,
      CVE-2017-0089, CVE-2017-0090)

    - Multiple information disclosure vulnerabilities exist
      in Windows Uniscribe that allow an unauthenticated,
      remote attacker to gain access to sensitive
      information by convincing a user to view a specially
      crafted website or open a specially crafted document
      file. (CVE-2017-0085, CVE-2017-0091, CVE-2017-0092,
      CVE-2017-0111, CVE-2017-0112, CVE-2017-0113,
      CVE-2017-0114, CVE-2017-0115, CVE-2017-0116,
      CVE-2017-0117, CVE-2017-0118, CVE-2017-0119,
      CVE-2017-0120, CVE-2017-0121, CVE-2017-0122,
      CVE-2017-0123, CVE-2017-0124, CVE-2017-0125,
      CVE-2017-0126, CVE-2017-0127, CVE-2017-0128)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/security/MS17-011");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, 10, and 2016.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

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

bulletin = 'MS17-011';
kbs = make_list(
  "4012212", #  Security Only for Windows 7 SP1 and Server 2008 R2 SP1
  "4012213", # Security Only for Windows 8.1 and Windows 2012 R2
  "4012214", # Security Only for Windows Server 2012
  "4012215", # Security only for Windows 7 SP1 and Server 2008 R2 SP1
  "4012216", # Security only for Windows 8.1 and Windows Server 2012 R2
  "4012217", # Monthly Rollup for Windows Server 2012
  "4012583", # Vista / 2008
  "4012606", # Win 10
  "4013198", # Win 10 1511 (AKA 10586)
  "4013429"  # Win  10 1607 (AKA 14393)
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
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Gdi32.dll", version:"6.0.6002.24067", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"4012583") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Gdi32.dll", version:"6.0.6002.19743", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"4012583") ||
  # Windows 7 / Server 2008 R2
  smb_check_rollup(os:"6.1", sp:1, rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4012212, 4012215)) ||
  # Windows Server 2012
  smb_check_rollup(os:"6.2", sp:0, rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4012214, 4012217)) ||
  # Windows 8.1 / Windows Server 2012 R2
  smb_check_rollup(os:"6.3", sp:0, rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4012213, 4012216)) ||
  # Windows 10
  smb_check_rollup(os:"10", sp:0, os_build:"10240", rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4012606)) ||
  # Windows 10 1511
  smb_check_rollup(os:"10", sp:0, os_build:"10586", rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4013198)) ||
  # Windows 10 1607 / Server 2016
  smb_check_rollup(os:"10", sp:0, os_build:"14393", rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4013429))
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
