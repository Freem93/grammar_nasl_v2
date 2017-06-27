#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97737);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/05/26 23:57:36 $");

  script_cve_id(
    "CVE-2017-0143",
    "CVE-2017-0144",
    "CVE-2017-0145",
    "CVE-2017-0146",
    "CVE-2017-0147",
    "CVE-2017-0148"
  );
  script_bugtraq_id(
    96703,
    96704,
    96705,
    96706,
    96707,
    96709
  );
  script_osvdb_id(
    153673,
    153674,
    153675,
    153676,
    153677,
    153678,
    155620,
    155634,
    155635
  );
  script_xref(name:"MSFT", value:"MS17-010");
  script_xref(name:"MSKB", value:"4012212");
  script_xref(name:"MSKB", value:"4012213");
  script_xref(name:"MSKB", value:"4012214");
  script_xref(name:"MSKB", value:"4012215");
  script_xref(name:"MSKB", value:"4012216");
  script_xref(name:"MSKB", value:"4012217");
  script_xref(name:"MSKB", value:"4012606");
  script_xref(name:"MSKB", value:"4013198");
  script_xref(name:"MSKB", value:"4013429");
  script_xref(name:"MSKB", value:"4012598");
  script_xref(name:"IAVA", value:"2017-A-0065");
  script_xref(name:"EDB-ID", value:"41891");
  script_xref(name:"EDB-ID", value:"41987");

  script_name(english:"MS17-010: Security Update for Microsoft Windows SMB Server (4013389) (ETERNALBLUE) (ETERNALCHAMPION) (ETERNALROMANCE) (ETERNALSYNERGY) (WannaCry) (EternalRocks)");
  script_summary(english:"Checks the version of the SYS files.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by the following vulnerabilities :

  - Multiple remote code execution vulnerabilities exist in
    Microsoft Server Message Block 1.0 (SMBv1) due to
    improper handling of certain requests. An
    unauthenticated, remote attacker can exploit these
    vulnerabilities, via a specially crafted packet, to
    execute arbitrary code. (CVE-2017-0143, CVE-2017-0144,
    CVE-2017-0145, CVE-2017-0146, CVE-2017-0148)

  - An information disclosure vulnerability exists in
    Microsoft Server Message Block 1.0 (SMBv1) due to
    improper handling of certain requests. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted packet, to disclose sensitive
    information. (CVE-2017-0147)

ETERNALBLUE, ETERNALCHAMPION, ETERNALROMANCE, and ETERNALSYNERGY are
four of multiple Equation Group vulnerabilities and exploits disclosed
on 2017/04/14 by a group known as the Shadow Brokers. WannaCry /
WannaCrypt is a ransomware program utilizing the ETERNALBLUE exploit,
and EternalRocks is a worm that utilizes seven Equation Group
vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS17-010");
  # https://blogs.technet.microsoft.com/msrc/2017/04/14/protecting-customers-and-evaluating-risk/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?321523eb");
  # https://blogs.technet.microsoft.com/mmpc/2017/05/12/wannacrypt-ransomware-worm-targets-out-of-date-systems/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7bec1941");
  # https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d9f569cf");
  script_set_attribute(attribute:"see_also", value:"https://github.com/stamparm/EternalRocks/");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, 10, and 2016. Microsoft has also
released emergency patches for Windows operating systems that are no
longer supported, including Windows XP, 2003, and 8.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"in_the_news", value:"true");
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

bulletin = 'MS17-010';
kbs = make_list(
  "4012212",
  "4012213",
  "4012214",
  "4012215",
  "4012216",
  "4012217",
  "4012606",
  "4013198",
  "4013429",
  "4012598"
);

vuln = 0;

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2',vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows Embedded" >< productname)
  exit(0, "Nessus does not support bulletin / patch checks for Windows Embedded.");

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share))
  audit(AUDIT_SHARE_FAIL, share);

if (
  ##############
  ## MAY 2017 ##
  ##############

  # Windows XP SP2
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"srv.sys", version:"5.2.3790.6021", min_version:"5.2.3790.3000", dir:"\system32\drivers", bulletin:bulletin, kb:"4012598", arch:"x64") ||
  # Windows XP SP3
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"srv.sys", version:"5.1.2600.7208", min_version:"5.1.2600.5000", dir:"\system32\drivers", bulletin:bulletin, kb:"4012598", arch:"x86") ||
  # Windows Server 2003 SP2
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"srv.sys", version:"5.2.3790.6021", min_version:"5.2.3790.3000", dir:"\system32\drivers", bulletin:bulletin, kb:"4012598") ||
  # Windows 8
  (
    ("Windows 8" >< productname && "Windows 8.1" >!< productname && "2012" >!< productname)
    &&
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"srv.sys", version:"6.2.9200.22099", min_version:"6.2.9200.16000", dir:"\system32\drivers", bulletin:bulletin, kb:"4012598")
  )
  ||

  ##############
  ## MAR 2017 ##
  ##############

  # Windows Vista Service Pack 2 / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"srv.sys", version:"6.0.6002.19743", min_version:"6.0.6002.18000", dir:"\system32\drivers", bulletin:bulletin, kb:"4012598") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"srv.sys", version:"6.0.6002.24067", min_version:"6.0.6002.20000", dir:"\system32\drivers", bulletin:bulletin, kb:"4012598") ||

  # Windows 7 / Windows Server 2008 R2
  smb_check_rollup(os:"6.1", sp:1, rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4012212, 4012215)) ||

  # Windows Server 2012
  (
    "Windows 8" >!< productname
    &&
    smb_check_rollup(os:"6.2", sp:0, rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4012214, 4012217))
  ) ||

  # Windows 8.1 / Windows Server 2012 R2
  smb_check_rollup(os:"6.3", sp:0, rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4012213, 4012216)) ||

  # Windows 10
  smb_check_rollup(os:"10", sp:0, os_build:"10240", rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4012606)) ||

  # Windows 10 1511
  smb_check_rollup(os:"10", sp:0, os_build:"10586", rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4013198)) ||

  # Windows 10 1607 / Windows Server 2016
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
