#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93469);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/09 21:04:54 $");

  script_cve_id(
    "CVE-2016-3346",
    "CVE-2016-3352",
    "CVE-2016-3368",
    "CVE-2016-3369"
  );
  script_bugtraq_id(
    92846,
    92847,
    92850,
    92852
  );
  script_osvdb_id(
    144183,
    144184,
    144185,
    144186
  );
  script_xref(name:"MSFT", value:"MS16-110");
  script_xref(name:"IAVA", value:"2016-A-0250");

  script_name(english:"MS16-110: Security Update for Microsoft Windows (3178467)");
  script_summary(english:"Checks the version of the DLL files.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple vulnerabilities :

  - An elevation of privilege vulnerability exists due to a
    failure to properly enforce permissions when loading
    specially crafted DLLs. A local attacker can exploit
    this vulnerability to execute arbitrary code with
    administrator privileges. (CVE-2016-3346)

  - An information disclosure vulnerability exists due to a
    failure to properly validate NT LAN Manager (NTLM)
    Single Sign-On (SSO) requests during Microsoft Account
    (MSA) login sessions. An unauthenticated, remote
    attacker can exploit this vulnerability, by convincing a
    user to load a malicious document that initiates an NTLM
    SSO validation request or to visit a malicious website
    or SMB / UNC path destination, to disclose a user's NTLM
    password hash. (CVE-2016-3352)

  - A remote code execution vulnerability exists due to
    improper handling of objects in memory. A remote
    attacker with a domain user account can exploit this
    vulnerability, via a specially crafted request, to
    execute arbitrary code with elevated permissions.
    (CVE-2016-3368)

  - A denial of service vulnerability exists due to improper
    handling of objects in memory. An unauthenticated,
    remote attacker can exploit this to cause the system to
    stop responding. (CVE-2016-3369)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-110");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS16-110';
kbs = make_list(
  "3184471",
  "3187754",
  "3185611",
  "3185614",
  "3189866"
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

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# Determine if Active Directory is enabled.
LDS_Enabled  = FALSE;
NTDS_Enabled = FALSE;

# NTDS check
ntds_value = get_registry_value(
  handle:hklm, item:"SYSTEM\CurrentControlSet\Services\NTDS\Parameters\DSA Database file");
if (!isnull(ntds_value))
  NTDS_Enabled = TRUE;

# LDS check
lds_value = get_registry_value(
  handle:hklm, item:"SYSTEM\CurrentControlSet\Services\DirectoryServices\Performance\InstallType");
if (!isnull(lds_value))
  LDS_Enabled = TRUE;

RegCloseKey(handle:hklm);
close_registry(close:FALSE);

# KB 3184471
if (
  (NTDS_Enabled || LDS_Enabled) &&
  (
  # Windows Vista Service Pack 2 / Windows Server 2008
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"ntdsai.dll", version:"6.0.6002.19686", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3184471") ||
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"ntdsai.dll", version:"6.0.6002.24008", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:"3184471") ||

    # Windows 7 / Windows Server 2008 R2
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"ntdsai.dll", version:"6.1.7601.23535", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:"3184471") ||

    # Windows Server 2012
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"ntdsai.dll", version:"6.2.9200.21953", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3184471") ||

    # Windows 8.1 / Windows Server 2012 R2
    hotfix_is_vulnerable(os:"6.3", sp:0, file:"ntdsai.dll", version:"6.3.9600.18435", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3184471")
  )
)
  vuln++;

# KB 3187754
if (
  
  # Windows 8.1 (not 2012 R2)
  "Windows 8.1" >< productname &&
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"lsasrv.dll", version:"6.3.9600.18454", dir:"\system32", bulletin:bulletin, kb:"3187754")

)
  vuln++;

# Windows 10
if (
  hotfix_is_vulnerable(os:"10", sp:0, file:"lsasrv.dll", version:"10.0.10240.17113", os_build:"10240", dir:"\system32", bulletin:bulletin, kb:"3185611") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"lsasrv.dll", version:"10.0.10586.589",   os_build:"10586", dir:"\system32", bulletin:bulletin, kb:"3185614") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"lsasrv.dll", version:"10.0.14393.187",    os_build:"14393", dir:"\system32", bulletin:bulletin, kb:"3189866")
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
  audit(AUDIT_HOST_NOT, 'affected');
}
