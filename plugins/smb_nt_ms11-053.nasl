#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55569);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/04/23 21:35:40 $");

  script_cve_id("CVE-2011-1265");
  script_bugtraq_id(48617);
  script_osvdb_id(73799);
  script_xref(name:"MSFT", value:"MS11-053");
  script_xref(name:"IAVA", value:"2011-A-0100");

  script_name(english:"MS11-053: Vulnerability in Bluetooth Stack Could Allow Remote Code Execution (2566220)");
  script_summary(english:"Checks the version of Bthport.sys");

  script_set_attribute(attribute:"synopsis", value:"Arbitrary code can be executed on the remote host through Bluetooth.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Windows Bluetooth stack that
is affected by a code execution vulnerability. By sending a series of
specially crafted Bluetooth packets to an affected system, an attacker
could install programs; view, change, or delete data; or create new
accounts with full user rights. Note that this vulnerability only
affects systems with Bluetooth capability.");

  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-053");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows Vista and 7.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS11-053';
kbs = make_list("2532531", "2561109");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(vista:'1,2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();
port   = kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

hcf_init = TRUE;

MAX_RECURSE = 1;

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
path  = ereg_replace(pattern:'^[A-Za-z](.*)', replace:'\\1', string:rootfile);



# Make sure this isn't Windows Server 2008 or Windows Server 2008 R2
rc = NetUseAdd(login:login, password:pass, domain:domain, share:'IPC$');
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

osver=NULL;
key = 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:'ProductName');
  if (!isnull(item)) osver = item[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);
if (isnull(osver)) exit(1, 'Couldn\'t determine the version of Windows running on the remote host.');
if (osver !~ '^(Windows 7|Windows Vista)')
  exit(0, 'The Windows version on the remote host is '+osver+' and thus is not affected.');

if (!is_accessible_share()) exit(1, 'is_accessible_share() failed.');

if (
  # Windows 7
  hotfix_is_vulnerable(os:'6.1', sp:1, file:'Bthport.sys', version:'6.1.7601.21716', min_version:'6.1.7601.21000', dir:'\\system32\\drivers', bulletin:bulletin, kb:'2532531') ||
  hotfix_is_vulnerable(os:'6.1', sp:1, file:'Bthport.sys', version:'6.1.7601.17607', min_version:'6.1.7601.17000', dir:'\\system32\\drivers', bulletin:bulletin, kb:'2532531') ||
  hotfix_is_vulnerable(os:'6.1', sp:0, file:'Bthport.sys', version:'6.1.7600.20955', min_version:'6.1.7600.20000', dir:'\\system32\\drivers', bulletin:bulletin, kb:'2532531') ||
  hotfix_is_vulnerable(os:'6.1', sp:0, file:'Bthport.sys', version:'6.1.7600.16805', min_version:'6.1.7600.16000', dir:'\\system32\\drivers', bulletin:bulletin, kb:'2532531') ||

  # Vista
  hotfix_is_vulnerable(os:'6.0', sp:2, file:'Bthport.sys', version:'6.0.6002.22629', min_version:'6.0.6002.20000', dir:'\\system32\\drivers', bulletin:bulletin, kb:'2532531') ||
  hotfix_is_vulnerable(os:'6.0', sp:2, file:'Bthport.sys', version:'6.0.6002.18457', min_version:'6.0.6002.18000', dir:'\\system32\\drivers', bulletin:bulletin, kb:'2532531') ||
  hotfix_is_vulnerable(os:'6.0', sp:1, file:'Bthport.sys', version:'6.0.6001.22204', min_version:'6.0.6001.20000', dir:'\\system32\\drivers', bulletin:bulletin, kb:'2561109')
)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();

  hotfix_check_fversion_end();
  exit(0);
}

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

patched = FALSE;
winsxs = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\WinSxS', string:rootfile);
files = list_dir(basedir:winsxs, level:0, dir_pat:'bth.inf', file_pat:'^bthport\\.sys$');

if (get_kb_item('SMB/WindowsVersion') == '6.0' && get_kb_item('SMB/CSDVersion') == 'Service Pack 1') kb = '2561109';
else kb = '2532531';

vuln = 0;
# Vista / Server 2008
versions = make_list('6.0.6001.22204', '6.0.6002.18457', '6.0.6002.22629');
max_versions = make_list('6.0.6001.99999', '6.0.6002.20000', '6.0.6002.99999');
vuln += hotfix_check_winsxs(os:'6.0', files:files, versions:versions, max_versions:max_versions, bulletin:bulletin, kb:kb);

# Windows 7 / Server 2008 R2
versions = make_list('6.1.7600.16805', '6.1.7600.20955', '6.1.7601.17607', '6.1.7601.21716');
max_versions = make_list('6.1.7600.20000', '6.1.7600.99999', '6.1.7601.20000', '6.1.7601.99999');
vuln += hotfix_check_winsxs(os:'6.1', files:files, versions:versions, max_versions:max_versions, bulletin:bulletin, kb:kb);

if (vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
hotfix_check_fversion_end();
audit(AUDIT_HOST_NOT, 'affected');
