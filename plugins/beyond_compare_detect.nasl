#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46241);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/12 17:12:43 $");

  script_name(english:"Beyond Compare Detection");
  script_summary(english:"Checks for Beyond Compare");

  script_set_attribute(attribute:"synopsis", value:
"There is an application for comparing files installed on the remote
Windows host.");

  script_set_attribute(attribute:"description", value:
"Scootersoft Beyond Compare, an application for comparing files and
folders, is installed on the remote Windows host.");

  script_set_attribute(attribute:"see_also", value:"http://www.scootersoftware.com/moreinfo.php");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");
include("audit.inc");
include("install_func.inc");

login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();
port    = kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}


path=NULL;
version=NULL;

key = "SOFTWARE\Scooter Software";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ '^Beyond Compare [0-9]+')
    {
      key2 = key + "\" + subkey;
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        item = RegQueryValue(handle:key2_h, item:"ExePath");
        if (!isnull(item))
        {
          path = item[1];
          RegCloseKey(handle:key2_h);
          break;
        }
        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, "Beyond Compare does not appear to be installed.");
}

share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:path);
exe = ereg_replace(pattern:'[A-Za-z]:(.*)', replace:"\1", string:path);
path = ereg_replace(pattern:'([A-Za-z]:.*)BCompare.exe', replace:"\1", string:path);

NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to the "+share+" share.");
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
  exit(1, "Can't open the file "+exe+".");
}

ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();

if (isnull(ver)) exit(1, "Can't extract Beyond Compare version number.");
version = join(ver, sep:'.');

kb_base = "SMB/Beyond Compare";
set_kb_item(name:kb_base+"/Version", value:version);
set_kb_item(name:kb_base+"/Path", value:path);
register_install(
  app_name:"Beyond Compare",
  path:path,
  version:version);

if (report_verbosity > 0)
{
  report =
    '\n' +
    'Version : ' + version + '\n' +
    'Path    : ' + path + '\n';
  security_note(port:port, extra:report);
}
else security_note(port:port);
