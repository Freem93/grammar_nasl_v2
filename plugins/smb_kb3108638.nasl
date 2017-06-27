#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86818);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/04/29 19:33:19 $");

  script_cve_id("CVE-2015-5307", "CVE-2015-8104");
  script_osvdb_id(130089, 130090);
  script_xref(name:"IAVB", value:"2015-B-0136");

  script_name(english:"MS KB3108638: Update for Windows Hyper-V to Address CPU Weakness");
  script_summary(english:"Checks the version of hvax64.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple denial of service
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by multiple denial of service
vulnerabilities that can be triggered with certain central processing
unit (CPU) chipsets. A local attacker with kernel-mode privileges on a
Hyper-V guest can exploit this to cause all Hyper-V guests to become
unresponsive.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/security/3108638");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/kb/3108638");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/kb/3108604");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/kb/3105213");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2008, 2008 R2, 8,
2012, 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "wmi_enum_server_features.nbin", "ms_bulletin_checks_possible.nasl");
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

kbs = make_list(
  '3105213', # Windows 10
  '3108604'  # All other versions of Windows
);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

# only 64-bit OSes are affected. the advisory doesn't explicitly say the 64-bit editions of Server 2012 and
# Server 2012 R2 are affected, but that's only because there are no 32-bit versions of those OSes
arch = get_kb_item_or_exit("SMB/ARCH", exit_code:1);
if (arch != "x64") audit(AUDIT_ARCH_NOT, "x64", arch);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# (Hyper-V ID = 20)
if (!get_kb_item('WMI/server_feature/20'))
{
  # could not determine if Hyper-V was enabled via wmi, so now check with registry
  # This is the key for the version of the integration services installer files,
  # which are only on the Hyper-V host.
  # Connect to remote registry.
  registry_init();
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  hyperv_reg = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\GuestInstaller\Version\Microsoft-Hyper-V-Guest-Installer");
  RegCloseKey(handle:hklm);
  close_registry(close:FALSE);

  if (!hyperv_reg)
  {
    NetUseDel();
    exit(0, "Systems without the Hyper-V role enabled are not affected by the vulnerability.");
  }
}

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 10
  hotfix_is_vulnerable(os:"10", file:"Hvax64.exe", version:"10.0.10240.16590", dir:"\system32", kb:"3105213") ||

  # Windows 8.1 / 2012 R2
  hotfix_is_vulnerable(os:"6.3", file:"Hvax64.exe", version:"6.3.9600.18114", dir:"\system32", kb:"3108604") ||

  # Windows 8 / 2012
  hotfix_is_vulnerable(os:"6.2", file:"Hvax64.exe", version:"6.2.9200.21679", min_version:"6.2.9200.21000", dir:"\system32", kb:"3108604") ||
  hotfix_is_vulnerable(os:"6.2", file:"Hvax64.exe", version:"6.2.9200.17562", dir:"\system32", kb:"3108604") ||

  # Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Hvax64.exe", version:"6.1.7601.23257", min_version:"6.1.7601.23000", dir:"\system32", kb:"3108604") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Hvax64.exe", version:"6.1.7601.19052", dir:"\system32", kb:"3108604") ||

  # Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Hvax64.exe", version:"6.0.6002.23844", min_version:"6.0.6002.23000", dir:"\system32", kb:"3108604") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Hvax64.exe", version:"6.0.6002.19534", min_version:"6.0.6002.18000", dir:"\system32", kb:"3108604")
)
{
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
