#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69925);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/12 02:12:33 $");

  script_name(english:"Cisco Secure ACS for Windows Installed");
  script_summary(english:"Checks for Cisco Secure ACS for Windows");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host has an access control application installed.");
  script_set_attribute(attribute:"description", value:
"Cisco Secure ACS for Windows, an access control application, is
installed on the remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/sw/secursw/ps2086/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:secure_access_control_for_windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

name   = kb_smb_name();
port   = kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

app = 'Cisco Secure Access Control Server for Windows';
path = NULL;

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Cisco";
subkeys = get_registry_subkeys(handle:hklm, key:key);
foreach subkey (subkeys)
{
  if (subkey =~ '^CiscoSecure ACS v[0-9\\.]+')
  {
    key = key + '\\' + subkey + "\Setup\BaseDir";
    path = get_registry_value(handle:hklm, item:key);
    break;
  }
}

RegCloseKey(handle:hklm);
if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}
close_registry(close:FALSE);

share = hotfix_path2share(path:path);
exe = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\bin\csadmin.exe", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
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
  audit(AUDIT_UNINST, app);
}

version = NULL;
fsize = GetFileSize(handle:fh);
off = 0;
while (off < fsize)
{
  data = ReadFile(handle:fh, length:10240, offset:off);
  if (strlen(data) == 0) break;

  if ('%s v%s, Copyright' >< data && 'Cisco Systems Inc' >< data)
  {
    chunk = strstr(data, 'Cisco Systems Inc') - 'Cisco Systems Inc';
    chunk = chunk - strstr(chunk, 'updateDBDirect');
    chunk = chomp(chunk);
    chunk = substr(chunk, 2, strlen(chunk) - 2);

    if (chunk =~ '^[0-9]+\\.[0-9]+\\([0-9]+\\.[0-9]+\\)([0-9]+)?')
    {
      version = chunk;
      break;
    }
  }
  off += 10240;
}
CloseFile(handle:fh);
NetUseDel();

if (isnull(version))
  audit(AUDIT_VER_FAIL, path + "\bin\csutil.exe");

version = str_replace(string:version, find:'(', replace:'.');

# Remove or replace the trailing ')' character
if (version =~ '^.*[0-9]+$')
  version = str_replace(string:version, find:')', replace:'.');
else version = str_replace(string:version, find:')', replace:'');


kb_base = 'SMB/Cisco Secure ACS for Windows/';
set_kb_item(name:kb_base + 'Path', value:path);
set_kb_item(name:kb_base + 'Version', value:version);

register_install(
  app_name:app,
  path:path,
  version:version,
  cpe:"cpe:/a:cisco:secure_access_control_for_windows");

if (report_verbosity > 0)
{
  report +=
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
