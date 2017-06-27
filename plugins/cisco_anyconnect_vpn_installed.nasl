#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(54953);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/12 17:12:43 $");

  script_name(english:"Cisco AnyConnect Secure Mobility Client Detection");
  script_summary(english:"Checks if the AnyConnect client is installed");

  script_set_attribute(attribute:"synopsis", value:"There is a VPN client installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"Cisco AnyConnect Secure Mobility Client (formerly known as Cisco
AnyConnect VPN Client) is installed on the remote Windows host. This
software can be used for secure connectivity.");
  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/ps10884/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_hotfixes.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");
include("install_func.inc");

install_num = 0;

get_kb_item_or_exit('SMB/Registry/Enumerated');

# Connect to the appropriate share.
name   = kb_smb_name();
port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();





if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:'IPC$');
if (rc != 1)
{
  NetUseDel();
  exit(1, 'Can\'t connect to IPC$ share.');
}

# Connect to remote registry
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, 'Can\'t connect to remote registry.');
}

key_list = make_list('SOFTWARE\\Cisco\\Cisco AnyConnect VPN Client',
                     'SOFTWARE\\Cisco\\Cisco AnyConnect Secure Mobility Client');

install_paths = make_list();

foreach key (key_list)
{
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:'InstallPathWithSlash');
    if (!isnull(item))
    {
      install_paths = make_list(install_paths, item[1]);
    }
    RegCloseKey(handle:key_h);
  }
}

RegCloseKey(handle:hklm);

if (max_index(install_paths) == 0)
{
  NetUseDel();
  exit(0, 'Cisco AnyConnect VPN Client was not detected on the remote host.');
}
else NetUseDel(close:FALSE);

report = '';


foreach path (install_paths)
{
  share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:path);
  exe = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1vpnui.exe', string:path);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, 'Can\'t connect to '+share+' share.');
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
    NetUseDel(close:FALSE);
    continue;
  }

  version = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
  NetUseDel(close:FALSE);

  if (isnull(version))
    continue;
  else
    version = join(version, sep:'.');

  report +=
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';

  set_kb_item(name:'SMB/cisco_anyconnect/' + install_num + '/path', value:path);
  set_kb_item(name:'SMB/cisco_anyconnect/' + install_num + '/version', value:version);
  register_install(
    app_name:"Cisco AnyConnect Secure Mobility Client",
    path:path,
    version:version,
    cpe:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  install_num++;
}

NetUseDel();

if(report != '')
{
  set_kb_item(name:'SMB/cisco_anyconnect/Installed', value:TRUE);
  set_kb_item(name:'SMB/cisco_anyconnect/NumInstalled', value:install_num);
  if (report_verbosity > 0)
    security_note(port:port, extra:report);
  else security_note(port);
  exit(0);
}
