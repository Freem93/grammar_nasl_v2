#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(56691);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/12 17:12:46 $");

  script_cve_id("CVE-2011-3179");
  script_bugtraq_id(50433);
  script_osvdb_id(76729);

  script_name(english:"Novell Messenger Server Memory Information Disclosure");
  script_summary(english:"Checks version of Novell Messenger");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an instant messaging product installed
that is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The installed version of Novell Messenger Server, formerly known as
GroupWise Messenger, is earlier than 2.2.1. It thus is potentially
affected by an information disclosure vulnerability whereby a remote,
unauthenticated attacker could send commands that would force the
Messenger server process to return the contents of arbitrary memory
locations. This data could potentially include strings containing the
credentials used by Messenger to authenticate to directory services.");

  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/viewContent.do?externalId=7009634");
  script_set_attribute(attribute:"solution", value:"Upgrade to Novell Messenger 2.2.1 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:groupwise_messenger");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('smb_func.inc');

if (report_paranoia < 2)
{
  status = get_kb_item_or_exit('SMB/svc/nnmMessagingAgent');
  if (status != SERVICE_ACTIVE) exit(0, 'The Novell Messaging Agent Service is installed but not active.');
}

login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();
port   = kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:'IPC$');
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,"IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

path = NULL;
key = 'SOFTWARE\\NOVELL\\Messenger\\MessagingAgent\\CurrentVersion';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:'Pathname');
  if (!isnull(item))
  {
    path = item[1];
    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, 'Novell Messenger Server wasn\'t detected on the remote host.');
}

share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:path);
path = ereg_replace(pattern:'^[A-Za-z]:(.*)\\\\[A-Za-z]+.dll', replace:'\\1', string:path);
exe = path + '\\nmma.exe';

NetUseDel(close:FALSE);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
}

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
  exit(1, 'Couldn\'t open file \''+path+'\\nmma.exe\'.');
}

ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();

if (isnull(ver)) exit(1, "Couldn't get file version of '"+(share-'$')+":"+exe+"'.");

version = ver[0] + '.' + ver[1] + '.' + ver[2];
if (ver_compare(ver:ver, fix:'2.2.1.0') == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + (share-'$')+":"+path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.2.1\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, 'The Novell Messenger Server '+version+' install on the host is not affected.');
