#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97745);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/05/26 23:57:36 $");

  script_cve_id(
    "CVE-2017-0021",
    "CVE-2017-0051",
    "CVE-2017-0074",
    "CVE-2017-0075",
    "CVE-2017-0076",
    "CVE-2017-0095",
    "CVE-2017-0096",
    "CVE-2017-0097",
    "CVE-2017-0098",
    "CVE-2017-0099",
    "CVE-2017-0109"
  );
  script_bugtraq_id(
    96020,
    96026,
    96636,
    96639,
    96640,
    96641,
    96642,
    96644,
    96698,
    96699,
    96701
  );
  script_osvdb_id(
    153661,
    153662,
    153663,
    153664,
    153665,
    153666,
    153667,
    153668,
    153669,
    153670,
    153671
  );
  script_xref(name:"MSFT", value:"MS17-008");
  script_xref(name:"MSKB", value:"3211306");
  script_xref(name:"MSKB", value:"4012212");
  script_xref(name:"MSKB", value:"4012213");
  script_xref(name:"MSKB", value:"4012214");
  script_xref(name:"MSKB", value:"4012215");
  script_xref(name:"MSKB", value:"4012216");
  script_xref(name:"MSKB", value:"4012217");
  script_xref(name:"MSKB", value:"4012606");
  script_xref(name:"MSKB", value:"4013198");
  script_xref(name:"MSKB", value:"4013429");
  script_xref(name:"IAVA", value:"2017-A-0061");

  script_name(english:"MS17-008: Security Update for Windows Hyper-V (4013082)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple vulnerabilities :

  - Multiple remote code execution vulnerabilities exist due
    to improper validation of vSMB packets. An attacker on a
    guest operating system can exploit these
    vulnerabilities, via a specially crafted application, to
    execute arbitrary code on the host. (CVE-2017-0021,
    CVE-2017-0095)

  - Multiple denial of service vulnerabilities exist due to
    improper validation of input from a privileged user on a
    guest operating system. An attacker with a privileged
    account on a guest operating system can exploit these
    vulnerabilities, via a specially crafted application, to
    crash the host machine. (CVE-2017-0051, CVE-2017-0074,
    CVE-2017-0076, CVE-2017-0097, CVE-2017-0098,
    CVE-2017-0099)

Note that customers who have not enabled the Hyper-V role are not
affected.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms17-008");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2008, 7, 2008 R2,
2012, 8.1, 2012 R2, 10 and 2016.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2017/03/14");
  script_set_attribute(attribute:"patch_publication_date",value:"2017/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/15");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "wmi_enum_server_features.nbin", "ms_bulletin_checks_possible.nasl", "smb_check_rollup.nasl");
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

bulletin = 'MS17-008';
kbs = make_list(
  "3211306",
  "4012212",
  "4012213",
  "4012214",
  "4012215",
  "4012216",
  "4012217",
  "4012606",
  "4013198",
  "4013429"
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
arch = get_kb_item_or_exit('SMB/ARCH', exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);
if (arch == "x86") audit(AUDIT_OS_SP_NOT_VULN);

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
  hyperv_reg = get_registry_value(handle:hklm, item:"SYSTEM\CurrentControlSet\Services\EventLog\System\Microsoft-Windows-Hyper-V-Hypervisor\EventMessageFile");
  RegCloseKey(handle:hklm);
  close_registry(close:TRUE);

  if (!hyperv_reg)
  {
    exit(0, "Systems without the Hyper-V role enabled are not affected by the vulnerability.");
  }
}

systemroot = hotfix_get_systemroot();
if (!systemroot) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');

port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

winsxs = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\WinSxS", string:systemroot);
winsxs_share = hotfix_path2share(path:systemroot);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:winsxs_share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, winsxs_share);
}

files = list_dir(basedir:winsxs, level:0, dir_pat:"amd64_wvms_pp.inf_31bf3856ad364e35_", file_pat:"^vmswitch\.sys$", max_recurse:1);

if (
  #key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\ApplicabilityEvaluationCache\Package_for_KB3211306~31bf3856ad364e35~amd64~~6.0.1.2";
  # Vista / Windows Server 2008
  hotfix_check_winsxs(os:'6.0',
                      sp:2,
                      files:files,
                      versions:make_list('6.0.6002.19747', '6.0.6002.23906'),
                      max_versions:make_list('6.0.6002.24070', '6.0.6002.99999'),
                      bulletin:bulletin,
                      kb:'3211306') ||

  # Windows 7 / Server 2008 R2
  smb_check_rollup(os:"6.1", sp:1, rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4012212, 4012215)) ||
  # Windows Server 2012
  smb_check_rollup(os:"6.2", sp:0, rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4012214, 4012217)) ||
  # Windows 8.1 / Windows Server 2012 R2
  smb_check_rollup(os:"6.3", sp:0, rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4012213, 4012216)) ||
  # Windows 10 / Windows Server 2016
  smb_check_rollup(os:"10", sp:0, os_build:"10240", rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4012606)) ||
  smb_check_rollup(os:"10", sp:0, os_build:"10586", rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4013198)) ||
  smb_check_rollup(os:"10", sp:0, os_build:"14393", rollup_date:"03_2017", bulletin:bulletin, rollup_kb_list:make_list(4013429))
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
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}
