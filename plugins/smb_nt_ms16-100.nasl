#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92822);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/09 21:04:54 $");

  script_cve_id("CVE-2016-3320");
  script_bugtraq_id(92304);
  script_osvdb_id(142729);
  script_xref(name:"MSFT", value:"MS16-100");
  script_xref(name:"IAVB", value:"2016-B-0122");

  script_name(english:"MS16-100: Security Update for Secure Boot (3179577)");
  script_summary(english:"Checks the version of tpmtasks.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a security bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by a security bypass vulnerability in Secure Boot
due to improper handling of malicious boot managers. An attacker with
administrative privileges can exploit this vulnerability to bypass
code integrity checks and load test-signed executables and drivers.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-100");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2012, 8.1, RT 8.1,
2012 R2, and 10. Alternatively, as a workaround, configure BitLocker
to use Trusted Platform Module (TPM)+PIN protection or disable Secure
Boot integrity protection of BitLocker per the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
include("smb_reg_query.inc");
include("misc_func.inc");
include("datetime.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS16-100';
kbs = make_list('3172729');
rls_vuln = FALSE;
vuln = FALSE;

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
os_version = get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);
local_arch = get_kb_item("SMB/ARCH");

if(hotfix_check_sp_range(win8:'0', win81:'0', win10:'0') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "Windows 8.1" >!< productname)
  audit(AUDIT_OS_SP_NOT_VULN);

systemroot = hotfix_get_systemroot();
if (!systemroot) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');

# No file version to check in windows 10
# So check registry to see if update was installed.
if(os_version == "10")
{
  registry_init();
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

  # Check release (10 base and 1511 are vuln, 1607 is not)
  key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion";
  release = NULL;

  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    release = RegQueryValue(handle:key_h, item:'ReleaseId');
    if (!isnull(release)) release = release[1];

    RegCloseKey(handle:key_h);
  }

  if(release == "1511" || empty_or_null(release)) rls_vuln = TRUE;

  if(local_arch == "x64")
  {
    key="SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\Package_1_for_KB3172729~31bf3856ad364e35~amd64~~10.0.1.1";
  }
  else
  {
    key="SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages\Package_1_for_KB3172729~31bf3856ad364e35~x86~~10.0.1.1";
  }
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:'InstallName');
    if (!isnull(value)) entry = value[1];

    RegCloseKey(handle:key_h);
  }

  RegCloseKey(handle:hklm);
  NetUseDel(close:FALSE);

  if ("KB3172729" >< entry || !rls_vuln)
  {
    audit(AUDIT_HOST_NOT, 'affected');
  }

  vuln = TRUE;
  report = '\nKB3046269 is not installed on this Windows 10 System\n';
  hotfix_add_report(bulletin:bulletin, kb:"3172729", report);
}
if (
  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"tpmtasks.dll", version:"6.3.9600.18408", dir:"\system32", bulletin:bulletin, kb:"3172729") ||

  # Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"tpmtasks.dll", version:"6.2.9200.21926", dir:"\system32", bulletin:bulletin, kb:"3172729") ||

  vuln
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
