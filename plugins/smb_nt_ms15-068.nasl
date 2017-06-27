#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84762);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/07/19 04:43:59 $");

  script_cve_id("CVE-2015-2361", "CVE-2015-2362");
  script_osvdb_id(124585, 124586);
  script_xref(name:"MSFT", value:"MS15-068");
  script_xref(name:"IAVB", value:"2015-B-0091");

  script_name(english:"MS15-068: Vulnerabilities in Windows Hyper-V Could Allow Remote Code Execution (3072000)");
  script_summary(english:"Checks the version of storvsp.sys or vmicvss.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple remote code execution
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by multiple remote code execution
vulnerabilities in Hyper-V :

  - An error exists in how Hyper-V handles packet size
    memory initialization in guest virtual machines. An
    authenticated attacker with access to a guest virtual
    machine can exploit this by running a specially crafted
    application to execute arbitrary code in a host context.
    (CVE-2015-2361)

  - An error exists in how Hyper-V initializes system data
    structures in guest virtual machines. An authenticated
    attacker with access to a guest virtual machine can
    exploit this by running a specially crafted application
    to execute arbitrary code in a host context.
    (CVE-2015-2362)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-068");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2008, 2008 R2, 8,
2012, 8.1, and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

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

bulletin = 'MS15-068';
kb       = '3046339';
kb2      = '3046359';
vuln     = 0;

kbs = make_list(kb, kb2);
if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

# Not embedded, Vista, Win7
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if (
  "Windows Embedded" >< productname ||
  "Vista" >< productname ||
  "Windows 7" >< productname
) exit(0, "The host is running "+productname+" and hence is not affected.");

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
}
else hyperv_reg = TRUE;

systemroot = hotfix_get_systemroot();
if (!systemroot) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');

share = hotfix_path2share(path:systemroot);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

####################################
# KB 3046359 ( storvsp.sys )
####################################
if (
  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, arch:"x64", file:"storvsp.sys", version:"6.3.9600.17723", min_version:"6.3.9600.16000", dir:"\system32\drivers", bulletin:bulletin, kb:kb2)
)
{
  vuln++;
}
NetUseDel(close:FALSE);

####################################
# KB 3046339 ( vmicvss.dll )
# SxS
####################################

login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();

if (hyperv_reg)
{
  winsxs = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\WinSxS", string:systemroot);
  winsxs_share = hotfix_path2share(path:systemroot);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:winsxs_share);
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL, winsxs_share);
  }

  files = list_dir(basedir:winsxs, level:0, dir_pat:"amd64_microsoft-hyper-v-i", file_pat:"^vmicvss\.dll$", max_recurse:1);
  if (
    # Windows 8.1 / Windows Server 2012 R2
    hotfix_check_winsxs(os:'6.3', sp:0, arch:"x64", files:files, versions:make_list('6.3.9600.17723'), max_versions:make_list('6.3.9600.99999'), bulletin:bulletin, kb:kb) ||

    # Windows 8 64bit / Windows Server 2012
    hotfix_check_winsxs(os:'6.2', sp:0, arch:"x64", files:files, versions:make_list('6.2.9200.21473'), max_versions:make_list('6.2.9200.99999'), bulletin:bulletin, kb:kb) ||
    hotfix_check_winsxs(os:'6.2', sp:0, arch:"x64", files:files, versions:make_list('6.2.9200.17361'), max_versions:make_list('6.2.9200.19999'), bulletin:bulletin, kb:kb) ||

    # Server 2008 R2
    hotfix_check_winsxs(os:'6.1', sp:1, arch:"x64", files:files, versions:make_list('6.1.7601.23045'), max_versions:make_list('6.1.7601.99999'), bulletin:bulletin, kb:kb) ||
    hotfix_check_winsxs(os:'6.1', sp:1, arch:"x64", files:files, versions:make_list('6.1.7601.18844'), max_versions:make_list('6.1.7601.21999'), bulletin:bulletin, kb:kb) ||

    # Server 2008
    hotfix_check_winsxs(os:'6.0', sp:2, arch:"x64", files:files, versions:make_list('6.0.6002.23684'), max_versions:make_list('6.0.6002.99999'), bulletin:bulletin, kb:kb) ||
    hotfix_check_winsxs(os:'6.0', sp:2, arch:"x64", files:files, versions:make_list('6.0.6002.19378'), max_versions:make_list('6.1.7601.21999'), bulletin:bulletin, kb:kb)
  )
  {
    vuln++;
  }
}

if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  if (!hyperv_reg)
    audit(AUDIT_HOST_NOT, 'affected (and Hyper-V was not detected)');
  else
    audit(AUDIT_HOST_NOT, 'affected');
}
