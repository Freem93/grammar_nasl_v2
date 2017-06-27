#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(58500);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/21 20:53:30 $");

  script_name(english:"Apple iTunes Mobile iOS Device Backup Enumeration (Windows)");
  script_summary(english:"Checks for mobile devices being backed up via iTunes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is used to backup data from a mobile device.");
  script_set_attribute(attribute:"description", value:
"The Apple iTunes installation on the remote Windows host is used by
at least one user to backup data from a mobile iOS device, such as an
iPhone, iPad, or iPod touch.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT203977");
  script_set_attribute(attribute:"solution", value:
"Make sure that the backup of mobile devices agrees with your
organization's acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "itunes_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('misc_func.inc');
include("audit.inc");

function parse_device_info(data)
{
  local_var section, value, idx_start, idx_end, datakey;
  local_var device_data, datakeys;

  if (empty_or_null(data)) return NULL;
  device_data = make_array();

  datakeys = make_list(
    'Device Name',
    'Last Backup Date',
    'Product Type',
    'Product Version',
    'Serial Number'
  );

  foreach datakey (datakeys)
  {
    # Extract each relevant key/value pair
    idx_start = stridx(data, '<key>'+datakey+'</key>');
    if (idx_start < 0) continue;

    if (datakey == 'Last Backup Date')
      idx_end = stridx(data, '</date>', idx_start);
    else
      idx_end = stridx(data, '</string>', idx_start);

    if (idx_end < 0) continue;
    section = substr(data, idx_start, idx_end);
    section = chomp(section);

    # Extract the vale from the key/value pair
    if (datakey == 'Last Backup Date')
    {
      idx_start = stridx(section, '<date>');
      if (idx_start >= 0)
      {
        value = substr(section, idx_start);
        value -= '<date>';
        value -= '<';
      }
    }
    else
    {
      idx_start = stridx(section, '<string>');
      if (idx_start >= 0)
      {
        value = substr(section, idx_start);
        value -= '<string>';
        value -= '<';
      }
    }
    if (!isnull(value))
    {
      device_data[datakey] = value;
    }
  }
  if (max_index(device_data) > 0) return device_data;
  else return NULL;
}

get_kb_item_or_exit('SMB/Registry/Enumerated');
if (isnull(get_kb_item('SMB/iTunes/Version'))) exit(0, 'iTunes doesn\'t appear to be installed on the remote host.');

# Get the install path
name    =  kb_smb_name();
port    =  kb_smb_transport();

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();


if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:'IPC$');
if (rc != 1)
{
  NetUseDel();
  exit(1,'Can\'t connect to IPC$ share.');
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1,'Can\'t connect to the remote registry.');
}

# Enumerate the local user directories that we will check
pdir = "";

# Find out where user directories are stored
rootdir = hotfix_get_systemroot();
if (isnull(rootdir))
{
  NetUseDel();
  exit(1, 'Couldn\'t determine the root directory.');
}
systemdrive = ereg_replace(pattern:'^([A-Za-z]:).*', replace:"\1", string:rootdir);
userdirs = make_list();


key = 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  # Enumerate the Domain User SIDs
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ 'S-1-5-21-[0-9\\-]+$')
    {
      key2 = key + '\\' + subkey;
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        item = RegQueryValue(handle:key2_h, item:'ProfileImagePath');
        if (!isnull(item))
        {
          if ('%SystemDrive%' >< item[1])
            item[1] = str_replace(string:item[1], find:'%SystemDrive%', replace:systemdrive);
          userdirs = make_list(userdirs, item[1]);
        }
      }
      RegCloseKey(handle:key2_h);
    }
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

userdevices = make_array();
backupdir = make_array();
numdevices = 0;
info = NULL;
# Look in each userdir to determine if any users are using itunes for backup
foreach userdir (userdirs)
{
  devicehash = NULL;
  share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:userdir);
  dirpat = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\AppData\Roaming\Apple Computer\MobileSync\Backup\*", string:userdir);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    debug_print('Couldn\'t connect to share '+share+'.');
    continue;
  }
  retx = FindFirstFile(pattern:dirpat);
  while (!isnull(retx[1]))
  {
    if (retx[1] != '.' && retx[1] != '..')
    {
      if (retx[1] =~ '^[0-9a-z]+$')
      {
        devicehash = retx[1];
        plistfile = (dirpat - '*') + devicehash + '\\Info.plist';
        fh = CreateFile(
          file:plistfile,
          desired_access:GENERIC_READ,
          file_attributes:FILE_ATTRIBUTE_NORMAL,
          share_mode:FILE_SHARE_READ,
          create_disposition:OPEN_EXISTING
        );
        if (isnull(fh))
        {
          debug_print('Couldn\'t open file \''+(share - '$')+plistfile+'.');
        }
        else
        {
          fsize = GetFileSize(handle:fh);
          if (fsize > 10240) fsize = 10240;
          if (fsize)
          {
            data = ReadFile(handle:fh, length:fsize, offset:0);
            ret = parse_device_info(data:data);
            if (!isnull(ret))
            {
              numdevices++;
              # Build the report
              info += '\n  File Path : ' + (share - '$') + plistfile;
              info +=
                '\n    Device Name      : ' + ret['Device Name'] +
                '\n    Product Type     : ' + ret['Product Type'] +
                '\n    Product Version  : ' + ret['Product Version'] +
                '\n    Serial Number    : ' + ret['Serial Number'] +
                '\n    Last Backup Date : ' + ret['Last Backup Date'] + '\n';
            }
          }
          CloseFile(handle:fh);
        }
      }
    }
    if (numdevices && !thorough_tests) retx[1] = NULL;
    else retx = FindNextFile(handle:retx);
  }
  NetUseDel(close:FALSE);
}
NetUseDel();

if (!isnull(info))
{
  if (report_verbosity > 0)
  {
    if (numdevices > 1)
    {
      a = 'Backups';
      s = 's were detected';
    }
    else
    {
      a = 'A backup';
      s = ' was detected';
    }
    report =
      '\n' + a + ' for the following mobile device' + s + ' on the remote' +
      '\nhost :\n' +
      info +
      '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else exit(0, 'No backups were detected for mobile iOS devices on the remote host.');
