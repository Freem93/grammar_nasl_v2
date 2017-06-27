#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55120);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/23 21:35:40 $");

  script_cve_id("CVE-2011-1889");
  script_bugtraq_id(48181);
  script_osvdb_id(72933);
  script_xref(name:"MSFT", value:"MS11-040");
  script_xref(name:"IAVA", value:"2011-A-0085");

  script_name(english:"MS11-040: Vulnerability in Threat Management Gateway Firewall Client Could Allow Remote Code Execution (2520426)");
  script_summary(english:"Checks version of FwcMgmt.exe");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through a firewall
client.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing Forefront Threat Management Gateway Client
security update 2520426.

The installed version of Forefront Threat Management Gateway is
affected by a vulnerability that may allow an attacker to execute
arbitrary code on the remote host.");

  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-040");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for Forefront Threat Management
Gateway.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:forefront_security");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");



get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS11-040';
kbs = make_list("2520426");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

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

path = NULL;
key = 'SOFTWARE\\Microsoft\\Firewall Client 2004';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:'InstallRoot');
  if (!isnull(item))
  {
    path = item[1];
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path)) exit(0, 'Microsoft Forefront Threat Management Gateway is not installed on the remote host.');

share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:path);
exe = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\FwcMgmt.exe', string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

version = NULL;
fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (isnull(fh))
{
  NetUseDel();
  exit(1, 'Couldn\'t open \''+path+'\\FwcMgmt.exe\'.');
}

prod = NULL;
ver = GetFileVersion(handle:fh);
ret = GetFileVersionEx(handle:fh);
if (!isnull(ret)) children = ret['Children'];
if (!isnull(children))
{
  varfileinfo = children['VarFileInfo'];
  if (!isnull(varfileinfo))
  {
    translation =
      (get_word(blob:varfileinfo['Translation'], pos:0) << 16) +
      get_word(blob:varfileinfo['Translation'], pos:2);
    translation = tolower(convert_dword(dword:translation, nox:TRUE));
  }
  stringfileinfo = children['StringFileInfo'];
  # nb: if varfileinfo is missing, use the first key for the translation
  if (isnull(varfileinfo) && !isnull(stringfileinfo))
  {
    foreach translation (keys(stringfileinfo))
      break;
  }
  if (!isnull(stringfileinfo) && !isnull(translation))
  {
    data = stringfileinfo[translation];
    if (!isnull(data)) prod = data['ProductName'];
    else
    {
      data = stringfileinfo[toupper(translation)];
      if (!isnull(data)) prod = data['ProductName'];
    }
  }
}

CloseFile(handle:fh);
NetUseDel();

if (isnull(ver))
{
  exit(1, 'Coulnd\'t get the version from \''+path+'\\FwcMgmt.exe\'.');
}
if (isnull(prod))
{
  exit(1, 'Couldn\'t get the product name from \''+path+'\\FwcMgmt.exe\'.');
}
if (prod != 'Forefront TMG Client')
{
  exit(0, 'The host is not affected because the firewall client is not Forefront Threat Management Gateway Client');
}


kb = '2520426';

version = join(sep:'.', ver);
if (
  ver[0] < 7 ||
  (ver[0] == 7 && ver[1] == 0 &&
    (
      ver[2] < 7734 ||
      (ver[2] == 7734 && ver[3] < 182)
    )
  )
)
{
  info =
    '\n  File              : ' + path + '\\FwcMgmt.exe' +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 7.0.7734.182\n';

  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_add_report(info, bulletin:bulletin, kb:kb);
  hotfix_security_hole();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, 'The host is not affected.');
}
