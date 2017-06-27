#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93470);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/03/21 13:39:52 $");

  script_cve_id(
    "CVE-2016-3305",
    "CVE-2016-3306",
    "CVE-2016-3371",
    "CVE-2016-3372",
    "CVE-2016-3373"
  );
  script_bugtraq_id(
    92812,
    92813,
    92814,
    92815,
    92845
  );
  script_osvdb_id(
    144187,
    144188,
    144189,
    144190,
    144191
  );

  script_xref(name:"MSFT", value:"MS16-111");
  script_xref(name:"IAVA", value:"2016-A-0242");
  script_name(english:"MS16-111: Security Update for Windows Kernel (3186973)");
  script_summary(english:"Checks the version of ntoskrnl.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple vulnerabilities :

  - Multiple elevation of privilege vulnerabilities exist
    due to improper handling of session objects. A local
    attacker can exploit these, via a specially crafted
    application, to hijack the session of another user.
    (CVE-2016-3305, CVE-2016-3306)

  - An flaw exists in the Windows Kernel API due to improper
    enforcement of permissions. A local attacker can exploit
    this, via a specially crafted application, to elevate
    privileges and thereby disclose potentially sensitive
    information. (CVE-2016-3371)

  - An elevation of privilege vulnerability exists in the
    Windows Kernel API due to improper enforcement of
    permissions. A local attacker can exploit this, via a
    specially crafted application, to impersonate processes,
    interject cross-process communication, or interrupt
    system functionality. (CVE-2016-3372)

  - An flaw exists in the Windows Kernel API due to
    improperly allowing access to sensitive registry
    information. A local attacker can exploit this, via a
    specially crafted application, to elevate privileges
    and thereby gain access to user account information.
    (CVE-2016-3373)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-111");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS16-111';
kbs = make_list(
  '3175024',
  '3185611',
  '3185614',
  '3189866'
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
  # 8.1 / 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"ntoskrnl.exe", version:"6.3.9600.18438", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3175024")  ||
  # 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"ntoskrnl.exe", version:"6.2.9200.21971", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3175024") ||
  # 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"ntoskrnl.exe", version:"6.1.7601.23539", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:"3175024") ||
  # Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"ntoskrnl.exe", version:"6.0.6002.24007", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3175024") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"ntoskrnl.exe", version:"6.0.6002.19680", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3175024") ||
  # 10 (1507)
  hotfix_is_vulnerable(os:"10", sp:0, file:"ntoskrnl.exe", version:"10.0.10240.17113", os_build:"10240", dir:"\system32", bulletin:bulletin, kb:"3185611") ||
  # 10 (1511)
  hotfix_is_vulnerable(os:"10", sp:0, file:"ntoskrnl.exe", version:"10.0.10586.589", os_build:"10586", dir:"\system32", bulletin:bulletin, kb:"3185614") ||
  # 10 (1607)
  hotfix_is_vulnerable(os:"10", sp:0, file:"ntoskrnl.exe", version:"10.0.14393.187", os_build:"14393", dir:"\system32", bulletin:bulletin, kb:"3189866")
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
  audit(AUDIT_HOST_NOT, 'affected');
}
