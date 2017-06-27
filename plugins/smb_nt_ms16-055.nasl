#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91005);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/07/13 20:59:28 $");

  script_cve_id(
    "CVE-2016-0168",
    "CVE-2016-0169",
    "CVE-2016-0170",
    "CVE-2016-0195"
  );
  script_bugtraq_id(
    89862,
    89863,
    89864,
    89901
  );
  script_osvdb_id(
    138321,
    138322,
    138323,
    138325
  );
  script_xref(name:"MSFT", value:"MS16-055");

  script_name(english:"MS16-055: Security Update for Microsoft Graphics Component (3156754)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple vulnerabilities :

  - Multiple information disclosure vulnerabilities exist in
    the Windows Graphics component. An unauthenticated,
    remote attacker can exploit these vulnerabilities by
    convincing a user to visit a specially crafted website
    or open open a specially crafted document, resulting in
    the disclosure of memory contents. (CVE-2016-0168,
    CVE-2016-0169)

  - A remote code execution vulnerability exists in the
    Windows Graphics component due to improper handling of
    objects in memory. An unauthenticated, remote attacker
    can exploit this vulnerability by convincing a user t
    visit a specially crafted website or open open a
    specially crafted document, resulting in the execution
    of arbitrary code in the context of the current user.
    (CVE-2016-0170)

  - A remote code execution vulnerability exists in the
    Direct3D component due to a use-after-free error. An
    unauthenticated, remote attacker can exploit this
    vulnerability by convincing a user to visit a specially
    crafted website or open open a specially crafted
    document, resulting in the execution of arbitrary code
    in the context of the current user. (CVE-2016-0170)

  - A remote code execution vulnerability exists in the
    Windows Imaging component due to improper handling of
    objects in memory. An unauthenticated, remote attacker
    can exploit this vulnerability by convincing a user t
    visit a specially crafted website or open open a
    specially crafted document, resulting in the execution
    of arbitrary code in the context of the current user.
    (CVE-2016-0195)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/security/ms16-055");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/10");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:microsoft:windows");
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

bulletin = 'MS16-055';

kbs = make_list(
  '3156013',
  '3156016',
  '3156019',
  '3156387',
  '3156421' 
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "Windows 8.1" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # 10 threshold 2 (aka 1511)
  hotfix_is_vulnerable(os:"10", sp:0, file:"gdi32.dll", version:"10.0.10586.306", min_version:"10.0.10586.0", dir:"\system32", bulletin:bulletin, kb:"3156421") ||

  # 10 RTM
  hotfix_is_vulnerable(os:"10", sp:0, file:"gdi32.dll", version:"10.0.10240.16841", dir:"\system32", bulletin:bulletin, kb:"3156387") ||

  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"Windowscodecs.dll", version:"6.3.9600.18302", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:'3156019') ||
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"gdi32.dll", version:"6.3.9600.18302", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:'3156013') ||
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"D3d10level9.dll", version:"6.3.9600.18302", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:'3156016') ||

  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Windowscodecs.dll", version:"6.2.9200.21831", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:'3156019') ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"gdi32.dll", version:"6.2.9200.21831", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:'3156013') ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"D3d10level9.dll", version:"6.2.9200.21830", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:'3156016') ||

  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Windowscodecs.dll", version:"6.1.7601.23418", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:'3156019') ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Windowscodecs.dll", version:"6.2.9200.21830", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:'3156019') ||
  # looks like LDR is new GDR for this file
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"gdi32.dll", version:"6.1.7601.23418", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:'3156013') ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"D3d10level9.dll", version:"6.1.7601.23432", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:'3156016') ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"D3d10level9.dll", version:"6.2.9200.21830", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:'3156016') ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"gdi32.dll", version:"6.0.6002.23950", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:'3156013') ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"gdi32.dll", version:"6.0.6002.19636", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:'3156013') ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Windowscodecs.dll", version:"7.0.6002.23950", min_version:"7.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:'3156019') ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Windowscodecs.dll", version:"7.0.6002.19636", min_version:"7.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:'3156019') ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"D3d10level9.dll", version:"7.0.6002.23950", min_version:"7.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:'3156016') ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"D3d10level9.dll", version:"7.0.6002.19647", min_version:"7.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:'3156016')
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
