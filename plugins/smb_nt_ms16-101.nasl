#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92823);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/05/24 14:05:10 $");

  script_cve_id(
    "CVE-2016-3237",
    "CVE-2016-3300"
  );
  script_bugtraq_id(
    92290,
    92296
  );
  script_osvdb_id(
    142732,
    142736
  );
  script_xref(name:"MSFT", value:"MS16-101");
  script_xref(name:"IAVA", value:"2016-A-0207");
  script_xref(name:"EDB-ID", value:"40409");

  script_name(english:"MS16-101: Security Update for Windows Authentication Methods (3178465)");
  script_summary(english:"Checks the version of the DLL files.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple vulnerabilities :

  - A security downgrade vulnerability exists in Kerberos
    due to improper handling of password change requests.
    A man-in-the-middle attacker can exploit this to cause
    the authentication protocol to fall back to the NT LAN
    Manager (NTLM) authentication protocol, resulting in a
    bypass of Kerberos authentication. (CVE-2016-3237)

  - An elevation of privilege vulnerability exists in
    Windows Netlogon due to a failure to properly establish
    secure communications to a domain controller. A local
    attacker who has access to a domain-joined machine that
    points to a domain controller running either Windows
    Server 2012 or 2012 R2 can exploit this vulnerability
    to gain elevated privileges via a specially crafted
    application. (CVE-2016-3300)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-101");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/09");

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
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS16-101';
kbs = make_list(
  "3167679",
  "3177108",
  "3192391",
  "3185330",
  "3192392",
  "3185331",
  "3192393",
  "3185332"
);
vuln = 0;

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "Windows 8.1" >!< productname)
  audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

# CVE-2016-3237
if (
  # Windows Vista Service Pack 2 / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"lsasrv.dll", version:"6.0.6002.19693", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3167679") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"lsasrv.dll", version:"6.0.6002.24017", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:"3167679") ||

  # 7 / 2008 R2
  smb_check_rollup(os:"6.1", sp:1, rollup_date:"10_2016", bulletin:bulletin, rollup_kb_list:make_list("3192391","3185330")) ||

 # 2012
  smb_check_rollup(os:"6.2", sp:1, rollup_date: "10_2016", bulletin:bulletin, rollup_kb_list:make_list("3192393","3185332")) ||
  
  # 8.1 / 2012 R2
  smb_check_rollup(os:"6.3", sp:1, rollup_date: "10_2016", bulletin:bulletin, rollup_kb_list:make_list("3192392","3185331")) 

)
  vuln++;

# CVE-2016-3300
if (
  # Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"lsasrv.dll", version:"6.2.9200.21941", dir:"\system32", bulletin:bulletin, kb:"3177108") ||

  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"netlogon.dll", version:"6.3.9600.18405", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3177108")

)
  vuln++;

# Windows 10
if (
  # Windows 10 1607
  smb_check_rollup(os:"10", sp:0, os_build:"14393", rollup_date: "10_2016", bulletin:bulletin, rollup_kb_list:make_list("3194798")) ||
  # Windows 10 1511
  smb_check_rollup(os:"10", sp:0, os_build:"10586", rollup_date: "10_2016", bulletin:bulletin, rollup_kb_list:make_list("3192441")) ||
  # Windows 10
  smb_check_rollup(os:"10", sp:0, os_build:"10240", rollup_date: "10_2016", bulletin:bulletin, rollup_kb_list:make_list("3192440"))
)
  vuln++;

if (vuln)
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
