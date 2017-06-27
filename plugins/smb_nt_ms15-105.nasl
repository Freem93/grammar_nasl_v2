#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85848);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/03/29 20:08:28 $");

  script_cve_id("CVE-2015-2534");
  script_bugtraq_id(76604);
  script_osvdb_id(127186);
  script_xref(name:"MSFT", value:"MS15-105");

  script_name(english:"MS15-105: Vulnerability in Windows Hyper-V Could Allow Security Feature Bypass (3091287)");
  script_summary(english:"Checks the version of vmsntfy.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a security bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a security bypass vulnerability
in Windows Hyper-V due to improper application of access control list
(ACL) configuration settings. A local attacker can exploit this, via a
specially crafted application, to cause Hyper-V to allow unintended
network traffic.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-105");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 8.1, 2012 R2, and
10.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

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

bulletin = 'MS15-105';
kbs = make_list('3081455', '3087088');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_NOTE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

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
  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, arch:"x64", file:"vmswitch.sys", version:"6.3.9600.18005", min_version:"6.3.9600.16000", dir:"\system32\drivers", bulletin:bulletin, kb:"3087088") ||

  # Windows 10
  hotfix_is_vulnerable(os:"10", sp:0, arch:"x64", file:"vmsif.dll", version:"10.0.10240.16384", min_version:"10.0.10240.16000", dir:"\system32", bulletin:bulletin, kb:"3081455")
)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_note();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
