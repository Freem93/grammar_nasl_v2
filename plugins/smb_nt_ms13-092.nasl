#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(70850);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/04/23 21:44:06 $");

  script_cve_id("CVE-2013-3898");
  script_bugtraq_id(63562);
  script_osvdb_id(99652);
  script_xref(name:"MSFT", value:"MS13-092");
  script_xref(name:"IAVB", value:"2013-B-0129");

  script_name(english:"MS13-092: Vulnerability in Hyper-V Could Allow Elevation of Privilege (2893986)");
  script_summary(english:"Checks version of hvax64.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is susceptible to an elevation of privilege
attack.");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by an elevation of privilege issue in
Hyper-V.  Successful exploitation of this vulnerability could result
elevated privileges, a denial of service (DoS) condition, or even in
arbitrary code being executed as 'System' in another virtual machine on
the shared Hyper-V host.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-092");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows 8 x64 and 2012.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "wmi_enum_server_features.nbin", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS13-092';
kb = '2893986';

kbs = make_list(kb);
if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# This bulletin only affects:
#   Windows 8 for x64-based Systems (Pro and Enterprise editions only)
#   Windows Server 2012 (Standard and Datacenter editions, and Hyper-V Server 2012 only)
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if (
  (
    "Windows 8 Enterprise" >!< productname &&
    "Windows 8 Pro" >!< productname &&
    "Windows Server 2012 Standard" >!< productname &&
    "Windows Server 2012 Datacenter" >!< productname
  ) ||
  "Windows Embedded" >< productname
) exit(0, "The host is running "+productname+" and hence is not affected.");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

# (Hyper-V ID = 20)
if (!get_kb_item('WMI/server_feature/20'))
{
  # could not determine if Hyper-V was enabled via wmi, so now check with registry
  # Connect to remote registry.
  registry_init();
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  hyperv_reg = get_registry_value(handle:hklm, item:"SOFTWARE\Classes\Microsoft.Virtualization.RemoteFileBrowsing\");
  RegCloseKey(handle:hklm);
  close_registry(close:FALSE);

  if (!hyperv_reg) exit(0, "Systems without the Hyper-V role enabled are not affected by the vulnerability.");
}

if (
  # Windows 8 64 bit & Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", arch:"x64", sp:0, file:"hvax64.exe", version:"6.2.9200.16729", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", arch:"x64", sp:0, file:"hvax64.exe", version:"6.2.9200.20840", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb)
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
