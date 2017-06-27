#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86373);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/10/25 16:45:47 $");

  script_cve_id(
    "CVE-2015-2549",
    "CVE-2015-2550",
    "CVE-2015-2552",
    "CVE-2015-2553",
    "CVE-2015-2554"
  );
  script_bugtraq_id(
    76994,
    76998,
    76999,
    77004,
    77014
  );
  script_osvdb_id(
    128808,
    128809,
    128810,
    128811,
    128812
  );
  script_xref(name:"MSFT", value:"MS15-111");
  script_xref(name:"IAVA", value:"2015-A-0242");

  script_name(english:"MS15-111: Security Update for Windows Kernel to Address Elevation of Privilege (3096447)");
  script_summary(english:"Checks the version of Ntoskrnl.exe or Winload.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by the following
vulnerabilities :

  - Multiple elevation of privilege vulnerabilities exist in
    the Windows kernel due to improper handling of objects
    in memory. A local attacker can exploit these
    vulnerabilities, via a specially crafted application, to
    execute arbitrary code in kernel mode. (CVE-2015-2549,
    CVE-2015-2550, CVE-2015-2554)

  - A security feature bypass vulnerability exists due to a
    failure to properly enforce the Windows Trusted Boot
    policy. A local attacker can exploit this, via a
    specially crafted Boot Configuration Data (BCD) setting,
    to disable code integrity checks, resulting in the
    execution of test-signed executables and drivers.
    Additionally, a local attacker can exploit this
    vulnerability to bypass Trusted Boot integrity
    validation for BitLocker and Device Encryption security
    features. (CVE-2015-2552)

  - An elevation of privilege vulnerability exists due to
    improper validation of junctions in certain scenarios in
    which mount points are being created. An
    unauthenticated, remote attacker can exploit this in
    conjunction with another vulnerability to execute
    arbitrary code in the context of the current user.
    (CVE-2015-2553)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-111");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/kb/3096447");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, RT, 2012, 8.1, RT 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS15-111';

kb = "3088195";
kbs = make_list("3088195","3097617");

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10: '0') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 10
  hotfix_is_vulnerable(os:"10", file:"Ntoskrnl.exe", version:"10.0.10240.16545", dir:"\system32", bulletin:bulletin, kb:"3097617") ||
  # Windows 8.1 / 2012 R2
  hotfix_is_vulnerable(os:"6.3", file:"winload.exe", version:"6.3.9600.18066", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # Windows 8 / 2012
  hotfix_is_vulnerable(os:"6.2", file:"Ntoskrnl.exe", version:"6.2.9200.21645", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", file:"Ntoskrnl.exe", version:"6.2.9200.17528", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # Windows 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Ntoskrnl.exe", version:"6.1.7601.23223", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Ntoskrnl.exe", version:"6.1.7601.19018", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Ntoskrnl.exe", version:"6.0.6002.23813", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Ntoskrnl.exe", version:"6.0.6002.19503", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb)

)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
