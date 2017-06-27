#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91012);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/07/13 20:59:28 $");
  script_cve_id(
    "CVE-2016-0171",
    "CVE-2016-0173",
    "CVE-2016-0174",
    "CVE-2016-0175",
    "CVE-2016-0176",
    "CVE-2016-0196",
    "CVE-2016-0197"
  );
  script_bugtraq_id(
    89860,
    90027,
    90052,
    90064,
    90065,
    90101,
    90102
  );
  script_osvdb_id(
    138332,
    138333,
    138334,
    138335,
    138336,
    138337,
    138338
  );
  script_xref(name:"MSFT", value:"MS16-062");

  script_name(english:"MS16-062: Security Update for Windows Kernel-Mode Drivers (3158222)");
  script_summary(english:"Checks the version of win32k.sys and dxgkrnl.sys.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple vulnerabilities :

  - Multiple privilege escalation vulnerabilities exist in
    the Windows kernel-mode driver due to a failure to
    properly handle objects in memory. An authenticated,
    remote attacker can exploit this, via a crafted
    application, to execute arbitrary code. (CVE-2016-0171,
    CVE-2016-0173, CVE-2016-0174, CVE-2016-0196)

  - A security feature bypass vulnerability exists in the
    Windows kernel. An authenticated, remote attacker can
    exploit this, via a crafted application, to bypass
    the Kernel Address Space Layout Randomization (KASLR)
    feature and retrieve the memory address of a kernel
    object. (CVE-2016-0175)

  - A privilege escalation vulnerability exists in the
    DirectX Graphics kernel subsystem due to a failure to
    properly handle objects in memory. An authenticated,
    remote attacker can exploit this, via a crafted
    application, to execute arbitrary code. (CVE-2016-0176)

  - A privilege escalation vulnerability exists in the
    DirectX Graphics kernel subsystem due to a failure to
    correctly map kernel memory and to handle objects in
    memory. An authenticated, remote attacker can exploit
    this, via a crafted application, to execute arbitrary
    code. (CVE-2016-0197)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-062");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS16-062';
kbs = make_list(
  "3153199",
  "3156017",
  "3156387",
  "3156421",
  "3158222"
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname)
  audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # 10 threshold 2 (aka 1511)
  hotfix_is_vulnerable(os:"10", sp:0, file:"win32kfull.sys", version:"10.0.10586.312", min_version:"10.0.10586.0", dir:"\system32", bulletin:bulletin, kb:"3156421") ||

  # 10 RTM
  hotfix_is_vulnerable(os:"10", sp:0, file:"win32kfull.sys", version:"10.0.10240.16847", dir:"\system32", bulletin:bulletin, kb:"3156387") ||

  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"win32k.sys", version:"6.3.9600.18302", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3153199") ||
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"dxgkrnl.sys", version:"6.3.9600.18302", min_version:"6.3.9600.16000", dir:"\system32\drivers", bulletin:bulletin, kb:"3156017") ||

  # Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"win32k.sys", version:"6.2.9200.21833", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3153199") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"dxgkrnl.sys", version:"6.2.9200.21831", min_version:"6.2.9200.16000", dir:"\system32\drivers", bulletin:bulletin, kb:"3156017") ||

  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"win32k.sys", version:"6.1.7601.23418", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:"3153199") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"dxgkrnl.sys", version:"6.1.7601.23418", min_version:"6.1.7600.18000", dir:"\system32\drivers", bulletin:bulletin, kb:"3156017") ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32k.sys", version:"6.0.6002.23950", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3153199") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32k.sys", version:"6.0.6002.19636", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:"3153199") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"dxgkrnl.sys", version:"7.0.6002.23950", min_version:"7.0.6002.23000", dir:"\system32\drivers", bulletin:bulletin, kb:"3156017") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"dxgkrnl.sys", version:"7.0.6002.19636", min_version:"7.0.6002.18000", dir:"\system32\drivers", bulletin:bulletin, kb:"3156017")
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

