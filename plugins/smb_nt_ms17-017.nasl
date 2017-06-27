#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97733);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/26 23:57:36 $");

  script_cve_id(
    "CVE-2017-0050",
    "CVE-2017-0101",
    "CVE-2017-0102",
    "CVE-2017-0103"
  );
  script_bugtraq_id(
    96025,
    96623,
    96625,
    96627
  );
  script_osvdb_id(
    153718,
    153719,
    153720,
    153721
  );
  script_xref(name:"MSFT", value:"MS17-017");
  script_xref(name:"MSKB", value:"4011981");
  script_xref(name:"MSKB", value:"4012212");
  script_xref(name:"MSKB", value:"4012213");
  script_xref(name:"MSKB", value:"4012214");
  script_xref(name:"MSKB", value:"4012215");
  script_xref(name:"MSKB", value:"4012216");
  script_xref(name:"MSKB", value:"4012217");
  script_xref(name:"MSKB", value:"4012606");
  script_xref(name:"MSKB", value:"4013198");
  script_xref(name:"MSKB", value:"4013429");
  script_xref(name:"IAVA", value:"2017-A-0068");

  script_name(english:"MS17-017: Security Update for Windows Kernel (4013081)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected multiple elevation of privilege
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple elevation of privilege
vulnerabilities :

  - An elevation of privilege vulnerability exists in the
    Windows Kernel API due to improper enforcement of
    permissions. A local attacker can exploit this, via a
    specially crafted application, to run processes in an
    elevated context. (CVE-2017-0050)

  - An elevation of privilege vulnerability exists in the
    Windows Transaction Manager due to improper handling of
    objects in memory. A local attacker can exploit this,
    via a specially crafted application, to run processes in
    an elevated context. (CVE-2017-0101)

  - An elevation of privilege vulnerability exists due to a
    failure to check the length of a buffer prior to copying
    memory. A local attacker can exploit this, by copying a
    file to a shared folder or drive, to gain elevated 
    privileges. (CVE-2017-0102)

  - An elevation of privilege vulnerability exists in the
    Windows Kernel API due to improper handling of objects
    in memory. A local attacker can exploit this, via a
    specially crafted application, to gain elevated
    privileges. (CVE-2017-0103)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms17-017");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, 10, and 2016.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2017/03/14");
  script_set_attribute(attribute:"patch_publication_date",value:"2017/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/14");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:microsoft:windows");
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

bulletin = 'MS17-017';
kbs = make_list(
  '4011981',
  '4012212',
  '4012213',
  '4012214',
  '4012215',
  '4012216',
  '4012217',
  '4012606',
  '4013198',
  '4013429'
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

date = "03_2017";
if (
  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"ntoskrnl.exe", version:"6.0.6002.19741", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"4011981") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"ntoskrnl.exe", version:"6.0.6002.24065", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:"4011981") ||
  # Windows 7 / Server 2008 R2
  smb_check_rollup(os:"6.1", sp:1, rollup_date:date, bulletin:bulletin, rollup_kb_list:make_list(4012212, 4012215)) ||
  # Windows 8.1 / Server 2012 R2
  smb_check_rollup(os:"6.3", sp:0, rollup_date:date, bulletin:bulletin, rollup_kb_list:make_list(4012213, 4012216)) ||
  # Server 2012
  smb_check_rollup(os:"6.2", sp:0, rollup_date:date, bulletin:bulletin, rollup_kb_list:make_list(4012214, 4012217)) ||
  # Windows 10
  smb_check_rollup(os:"10", sp:0, os_build:"10240", rollup_date:date, bulletin:bulletin, rollup_kb_list:make_list(4012606)) ||
  # Windows 10 1511
  smb_check_rollup(os:"10", sp:0, os_build:"10586", rollup_date:date, bulletin:bulletin, rollup_kb_list:make_list(4013198)) ||
  # Windows 10 1607 / Server 2016 x64
  smb_check_rollup(os:"10", sp:0, os_build:"14393", rollup_date:date, bulletin:bulletin, rollup_kb_list:make_list(4013429))
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
