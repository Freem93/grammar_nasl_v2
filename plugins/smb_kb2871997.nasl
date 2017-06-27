#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73990);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/02/06 20:45:10 $");

  script_xref(name:"IAVA", value:"2016-A-0327");

  script_name(english:"MS KB2871997: Update to Improve Credentials Protection and Management");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is missing an update to improve credentials
protection and management.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing one or more of the following Microsoft
updates: KB2871997, KB2973351, KB2975625, KB2982378, KB2984972,
KB2984976, KB2984981, KB2973501, or KB3126593. These updates are
needed to improve the protection against possible credential theft.

  - For Windows 7 / 2008 R2 :
    KB2984972, KB2871997, KB2982378, and KB2973351 are
    required; also,
    KB2984976 (if KB2592687 is installed) or
    KB2984981 (if KB2830477 is installed).

  - For Windows 8 / 2012 :
    KB2973501, KB2871997, and KB2973351 are required.

  - For Windows 8.1 / 2012 R2 :
    KB2973351 (if Update 1 is installed) or
    KB2975625 (if Update 1 isn't installed).

These updates provide additional protection for the Local Security
Authority (LSA), add a restricted administrative mode for Credential
Security Support Provider (CredSSP), introduce support for the
protected account-restricted domain user category, enforce stricter
authentication policies, add additional protection for users'
credentials, and add a restricted administrative mode for Remote
Desktop Connection and Remote Desktop Protocol.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/security/2871997.aspx");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 7, 2008 R2, 8,
2012, 8.1, and 2012 R2.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}

include("audit.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

##
# Checks the registry for the following key:
# HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential
#
# @return
#   NULL registry key is set to 0
#   STRING report addon
##
function wdigest_reg_check()
{
  local_var hklm, key, value, ret;

  ret = '';

  registry_init(full_access_check:FALSE);
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

  key = "SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential";
  value = get_registry_value(handle:hklm, item:key);

  RegCloseKey(handle:hklm);
  close_registry();

  # Only the value of 0 is acceptable
  if (empty_or_null(value) || value != '0')
  {
    ret = '\nA required registry setting is missing:\n' +
          '\nHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential = 0\n' +
          '\nMore information: https://blogs.technet.microsoft.com/kfalde/2014/11/01/kb2871997-and-wdigest-part-1/\n';
  }
  else ret = NULL;

  return ret;
}

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);
if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

win_ver = get_kb_item_or_exit("SMB/WindowsVersion");

kb = '2871997';

vuln = FALSE;

reg_rep = '';
missing_kbs = make_list();

# We need to check the registry in addition to the KB
if (
  # Windows 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"kerberos.dll", version:"6.1.7601.22616", min_version:"6.1.7601.21000", dir:"\system32", kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"kerberos.dll", version:"6.1.7601.18409", min_version:"6.1.7600.17000", dir:"\system32", kb:kb) ||
  # Windows 8 / 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"kerberos.dll", version:"6.2.9200.21012", min_version:"6.2.9200.20000", dir:"\system32", kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"kerberos.dll", version:"6.2.9200.16891", min_version:"6.2.9200.16000", dir:"\system32", kb:kb))
{
  vuln = TRUE;
  missing_kbs = make_list(missing_kbs, kb);
  reg_rep = wdigest_reg_check();
}
else if (
  win_ver == "6.1" ||
  win_ver == "6.2"
)
{
  reg_rep = wdigest_reg_check();
  if(!isnull(reg_rep))
    vuln = TRUE;
}

if (
  # Windows 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"lsasrv.dll", version:"6.1.7601.22712", min_version:"6.1.7601.21000", dir:"\system32", kb:'2973351') ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"lsasrv.dll", version:"6.1.7601.18496", min_version:"6.1.7600.17000", dir:"\system32", kb:'2973351') ||
  # Windows 8 / 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"lsasrv.dll", version:"6.2.9200.21132", min_version:"6.2.9200.20000", dir:"\system32", kb:'2973351') ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"lsasrv.dll", version:"6.2.9200.17013", min_version:"6.2.9200.16000", dir:"\system32", kb:'2973351') ||
  # Windows 8.1 / 2012 R2 (Update 1)
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"adtschema.dll", version:"6.3.9600.17193", min_version:"6.3.9600.17000", dir:"\system32", kb:'2973351'))
{
  vuln = TRUE;
  missing_kbs = make_list(missing_kbs, '2973351');
}
if(
  # Windows 8.1 / 2012 R2 (No Update 1)
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"lsasrv.dll", version:"6.3.9600.16670", min_version:"6.3.9600.16000", dir:"\system32", kb:'2975625')
)
{
  vuln = TRUE;
  missing_kbs = make_list(missing_kbs, '2975625');
}

if (
  # KB2982378
  # Windows 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"lsasrv.dll", version:"6.1.7601.22736", min_version:"6.1.7601.21000", dir:"\system32", kb:'2982378') ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"lsasrv.dll", version:"6.1.7601.18526", min_version:"6.1.7600.17000", dir:"\system32", kb:'2982378')
)
{
  vuln = TRUE;
  missing_kbs = make_list(missing_kbs, '2982378');
}

if (
  # Windows 7 / 2008 R2 (KB2984972)
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"credssp.dll", version:"6.1.7601.22750", min_version:"6.1.7601.21000", dir:"\system32", kb:'2984972') ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"credssp.dll", version:"6.1.7601.18540", min_version:"6.1.7600.17000", dir:"\system32", kb:'2984972')
)
{
  vuln = TRUE;
  missing_kbs = make_list(missing_kbs, '2984972');
}

if (
  # Windows 7 / 2008 R2 with KB2592687 installed (KB2984976)
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mstscax.dll", version:"6.2.9200.17053", min_version:"6.2.9200.16000", dir:"\system32", kb:'2984976') ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mstscax.dll", version:"6.2.9200.21172", min_version:"6.2.9200.20000", dir:"\system32", kb:'2984976')
)
{
  vuln = TRUE;
  missing_kbs = make_list(missing_kbs, '2984976');
}

if (
  # Windows 7 / 2008 R2 with KB2830477 installed (KB2984981)
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mstscax.dll", version:"6.3.9600.17223", min_version:"6.3.9600.16000", dir:"\system32", kb:'2984981')
)
{
  vuln = TRUE;
  missing_kbs = make_list(missing_kbs, '2984981');
}

if (
  # Windows 8 / 2012 (KB2973501)
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"mstscax.dll", version:"6.2.9200.17048", min_version:"6.2.9200.16000", dir:"\system32", kb:'2973501') ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"mstscax.dll", version:"6.2.9200.21166", min_version:"6.2.9200.20000", dir:"\system32", kb:'2973501')
)
{
  vuln = TRUE;
  missing_kbs = make_list(missing_kbs, '2973501');
}

if (
  # Windows 8.1 / 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"ntdll.dll", version:"6.3.9600.18202", min_version:"6.3.9600.16000", dir:"\system32", kb:'3126593')
  )
{
  # KB3147071 ships with a version of ntdll.dll that has, for some unknown reason, been decremented. This is a subsequent check to ensure that
  # the patch is installed, which has version 6.3.9600.18194, and other files, all modified on March 10, 2016, which have a version of
  # 6.3.9600.18264.
  if (
    hotfix_is_vulnerable(os:"6.3", sp:0, file:"ntdll.dll", version:"6.3.9600.18194", min_version:"6.3.9600.16000", dir:"\system32", kb:'3126593') &&
    ! hotfix_is_vulnerable(os:"6.3", sp:0, file:"kernelbase.dll", version:"6.3.9600.18264", min_version:"6.3.9600.16000", dir:"\system32", kb:'3126593') &&
    ! hotfix_is_vulnerable(os:"6.3", sp:0, file:"ntoskrnl.exe", version:"6.3.9600.18264", min_version:"6.3.9600.16000", dir:"\system32", kb:'3126593')
  )
  {
    vuln = TRUE;
    missing_kbs = make_list(missing_kbs, '3126593');
  }

}


if (
  # Windows 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"kerberos.dll", version:"6.2.9200.17637", min_version:"6.2.9200.15000", dir:"\system32", kb:'3126593') ||

  # Windows 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"lsasrv.dll", version:"6.1.7601.23334", min_version:"6.1.7601.21000", dir:"\system32", kb:'3126593') ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"lsasrv.dll", version:"6.1.7601.19131", min_version:"6.1.7600.17000", dir:"\system32", kb:'3126593') ||

  # Windows Vista / Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"advapi32.dll", version:"6.0.6002.19594", min_version:"6.0.6002.17000", dir:"\system32", kb:'3126593') ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"advapi32.dll", version:"6.0.6002.23905", min_version:"6.0.6002.21000", dir:"\system32", kb:'3126593')
)
{
  vuln = TRUE;
  missing_kbs = make_list(missing_kbs, '3126593');
}

# add additional information to the report to avoid confusion
if(!empty_or_null(missing_kbs))
{
  hotfix_add_report('\n  Missing KBs :');
  foreach kb (missing_kbs)
    hotfix_add_report('\n    ' + kb );
}

if (!empty_or_null(reg_rep))
  hotfix_add_report('\n'+reg_rep);

if(vuln)
{
  hotfix_security_note();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
