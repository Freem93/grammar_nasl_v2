#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
  script_id(48762);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2015/10/21 20:34:21 $");

  script_name(english:"MS KB2269637: Insecure Library Loading Could Allow Remote Code Execution");
  script_summary(english:"Checks version of ntdll.dll");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host may be vulnerable to code execution attacks.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing Microsoft KB2264107 or an associated
registry change, which provides a mechanism for mitigating binary
planting or DLL preloading attacks.

Insecurely implemented applications look in their current working
directory when resolving DLL dependencies. If a malicious DLL with the
same name as a required DLL is located in the application's current
working directory, the malicious DLL will be loaded.

A remote attacker could exploit this issue by tricking a user into
accessing a vulnerable application via a network share or WebDAV
folder where a malicious DLL resides, resulting in arbitrary code
execution.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/2269637");
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?960d4ef0"
  );
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2 :

http://support.microsoft.com/kb/2264107

Please note this update provides a method of mitigating a class of
vulnerabilities rather than fixing any specific vulnerabilities.
Additionally, these patches must be used in conjunction with the
'CWDIllegalInDllSearch' registry setting to have any effect. These
protections could be applied in a way that breaks functionality in
existing applications. Refer to the Microsoft advisory for more
information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("byte_func.inc");
include("audit.inc");


get_kb_item_or_exit('SMB/WindowsVersion');
if (hotfix_check_sp(win2k:6, xp:4, win2003:3, vista:3, win7:2) <= 0)
  exit(0, 'The host is not affected based on its version / service pack.');

if (!is_accessible_share()) exit(1, 'is_accessible_share() failed.');

if (
  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", file:"Ntdll.dll", version:"6.1.7600.20745", min_version:"6.1.7600.20000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.1", file:"Ntdll.dll", version:"6.1.7600.16625", min_version:"6.1.7600.16000", dir:"\system32") ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Ntdll.dll", version:"6.0.6002.22435", min_version:"6.0.6002.22000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Ntdll.dll", version:"6.0.6002.18279", min_version:"6.0.6002.18000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Ntdll.dll", version:"6.0.6001.22721", min_version:"6.0.6001.22000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Ntdll.dll", version:"6.0.6001.18499", min_version:"6.0.6001.18000", dir:"\system32") ||

  # Windows 2003 / XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Ntdll.dll", version:"5.2.3790.4737", dir:"\system32") ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Ntdll.dll", version:"5.1.2600.6007", dir:"\system32")
)
{
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}

hotfix_check_fversion_end();

# If ntdll.dll has been patched, check to see if is configured
# to prevent loading DLLs from the CWD (registry setting)
name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();
cwd_disabled = FALSE;

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to the remote registry.");
}

key = "SYSTEM\CurrentControlSet\Control\Session Manager";
item = 'CWDIllegalInDllSearch';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (isnull(key_h))
{
  NetUseDel();
  exit(1, "Can't access the 'HKLM\"+key+"' registry key.");
}

value = RegQueryValue(handle:key_h, item:item);
RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
NetUseDel();

kb_item = 'HKEY_LOCAL_MACHINE\\' + key + '\\' + item;

# No value is set by default.  If it has any valid value (other than 0 or
# nothing), we'll assume a policy has been decided on and put into place
if (
  !isnull(value) &&
  (value[1] == 0xffffffff || value[1] == 1 || value[1] == 2)
)
{
  cwd_disabled = TRUE;
  kb_name = 'SMB/Registry/' + 'HKLM' + kb_item - 'HKEY_LOCAL_MACHINE';
  kb_name = str_replace(string:kb_name, find:'\\', replace:'/');
  if (value[1] == 0xffffffff) kb_val = '0xffffffff';
  else kb_val = strcat(value[1]);
  set_kb_item(name:kb_name, value:kb_val);
  exit(0, 'KB2264107 is installed and '+item+' is set to '+kb_val+'.');
}

if (report_verbosity > 0)
{
  if (isnull(value) || value[1] == 0)
  {
    report =
      '\nntdll.dll has been upgraded by KB2264107 or a related, subsequent update,' +
      '\nbut the following registry entry has not been set :\n' +
      '\n' + kb_item + '\n';
  }
  else
  {
    report =
      '\nntdll.dll has been upgraded by KB2264107 or a related, subsequent update,' +
      '\nbut the following registry entry has an unrecognized value :\n' +
      '\n  Name  : ' + kb_item +
      '\n  Value : ' + value[1] + '\n';
  }
  security_hole(port:port, extra:report);
}
else security_hole(port);
