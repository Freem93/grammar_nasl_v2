#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97742);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/26 23:57:36 $");

  script_cve_id("CVE-2017-0022");
  script_bugtraq_id(96069);
  script_osvdb_id(153637);
  script_xref(name:"MSFT", value:"MS17-022");
  script_xref(name:"MSKB", value:"3216916");
  script_xref(name:"MSKB", value:"4012212");
  script_xref(name:"MSKB", value:"4012213");
  script_xref(name:"MSKB", value:"4012214");
  script_xref(name:"MSKB", value:"4012215");
  script_xref(name:"MSKB", value:"4012216");
  script_xref(name:"MSKB", value:"4012217");
  script_xref(name:"MSKB", value:"4012606");
  script_xref(name:"MSKB", value:"4013198");
  script_xref(name:"MSKB", value:"4013429");
  script_xref(name:"IAVA", value:"2017-A-0067");

  script_name(english:"MS17-022: Security Update for Microsoft XML Core Services (4010321)");
  script_summary(english:"Checks the file version of Msxml3.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by an information disclosure
vulnerability in Microsoft XML Core Services (MSXML) due to improper
handling of objects in memory. An unauthenticated, remote attacker can
exploit this vulnerability, by convincing a user to visit a
specially crafted website, to test for the presence of files on disk.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS17-022");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, 10, and 2016.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:xml_core_services");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"Windows : Microsoft Bulletins");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS17-022';
kbs = make_list(
  "3216916",
  "4012212",
  "4012213",
  "4012214",
  "4012215",
  "4012216",
  "4012217",
  "4012606",
  "4013198",
  "4013429");

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0',  win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname)
  audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 10 1607
  smb_check_rollup(os:"10", sp:0, os_build:"14393", rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4013429)) ||

  # Windows 10 1511
  smb_check_rollup(os:"10", sp:0, os_build:"10586", rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4013198)) ||

  # Windows 10
  smb_check_rollup(os:"10", sp:0, os_build:"10240", rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4012606)) ||

  # Windows 8.1 / Windows Server 2012 R2
  smb_check_rollup(os:"6.3", sp:0, rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4012213, 4012216)) ||

  # Windows Server 2012
  smb_check_rollup(os:"6.2", sp:0, rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4012214, 4012217)) ||

  # Windows 7 / 2008 R2
  smb_check_rollup(os:"6.1", sp:1, rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4012212, 4012215)) ||

  # Windows Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Msxml3.dll", version:"8.100.5014.0", dir:"\system32", bulletin:bulletin, kb:"3216916")
)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}
