#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90438);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/04/25 20:25:37 $");

  script_cve_id(
    "CVE-2016-0088",
    "CVE-2016-0089",
    "CVE-2016-0090"
  );
  script_bugtraq_id(
    85915,
    85916,
    85921
  );
  script_osvdb_id(
    136973,
    136974,
    136975
  );
  script_xref(name:"MSFT", value:"MS16-045");
  script_xref(name:"IAVB", value:"2016-B-0064");

  script_name(english:"MS16-045: Security Update for Windows Hyper-V (3143118)");
  script_summary(english:"Checks version of vmswitch.sys or vmsif.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple vulnerabilities :

  - An arbitrary code execution vulnerability exists in
    Hyper-V due to a failure to properly validate input from
    an authenticated user on a guest operating system. An
    attacker can exploit this, via a crafted application on
    the guest operating system, to execute arbitrary code on
    the host operating system. (CVE-2016-0088)

  - Multiple information disclosure vulnerabilities exists
    in Hyper-V due to a failure to properly validate input
    from an authenticated user on a guest operating system.
    An attacker can exploit this, via a crafted application
    on the guest operating system, to disclose memory
    information on the host operating system.
    (CVE-2016-0089, CVE-2016-0090)

Note that users who have not enabled the Hyper-V role are not affected
by these vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-045");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2012, 8.1,
2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

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

bulletin = 'MS16-045';
kbs = make_list('3147461', '3135456');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname)
  audit(AUDIT_OS_SP_NOT_VULN);

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
  close_registry(close:TRUE);

  if (!hyperv_reg)
    exit(0, "Systems without the Hyper-V role enabled are not affected by the vulnerability.");
}

systemroot = hotfix_get_systemroot();
if (!systemroot) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');

port = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

if(hotfix_check_fversion_init() != HCF_OK)
  audit(AUDIT_FN_FAIL, 'hotfix_check_fversion_init');

winsxs = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\WinSxS", string:systemroot);
winsxs_share = hotfix_path2share(path:systemroot);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:winsxs_share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, winsxs_share);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\ApplicabilityEvaluationCache\Package_for_KB3135456~31bf3856ad364e35~amd64~~6.2.1.3";

files = list_dir(basedir:winsxs, level:0, dir_pat:"amd64_microsoft-hyper-v-drivers-vmswitch_31bf3856ad364e35_", file_pat:"^vmswitch\.sys$", max_recurse:1);

files10 = list_dir(basedir:winsxs, level:0, dir_pat:"amd64_microsoft-hyper-v-d..s-vmswitch-netsetup_31bf3856ad364e35_", file_pat:"^vmsif\.dll$", max_recurse:1);

if(
  # Windows 10
  hotfix_check_winsxs(os:"10",
                      sp:0,
                      files:files10,
                      versions:make_list('10.0.10240.16766'),
                      max_versions:make_list('10.0.10240.99999'),
                      bulletin:bulletin,
                      kb:"3147461") ||

  # Windows 8.1 / Windows Server 2012 R2    
  hotfix_check_winsxs(os:'6.3',
                      sp:0,
                      files:files,
                      versions:make_list('6.3.9600.18258'),
                      max_versions:make_list('6.3.9600.99999'),
                      bulletin:bulletin,
                      kb:'3135456',
                      key:key) ||

  # Windows 8 / Windows Server 2012
  hotfix_check_winsxs(os:'6.2',
                      sp:0,
                      files:files,
                      versions:make_list('6.2.9200.21793'),
                      max_versions:make_list('6.2.9200.99999'),
                      bulletin:bulletin,
                      kb:'3135456',
                      key:key)
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
