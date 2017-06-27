#TRUSTED 6f5d7fe4451b4cb86f699300776c34559aedbd1b1d8b994ede1bd8476fd73f2df510eb75c7f6414d752b68ff7318b8ca24f2349716cf93119482fb074118a002f272ba377724096ff056efb42cf8dfa48c83ad8b56a13c7e538d9445c15ca75438ca4011dc29417808ef2b837537e1695f0efdab1d3f86d9ce7536bccf4824ca1fe72a3deb6991942f6e887fbb4ef2988528d37f6c1e0edd730e655f7d32c607e1247d36d2d1df3366a70c1d897f816e7a7a820693a2900ed9377d2127849dee18f51726dd9194a5091ef4413e2f2b29bbc50b7aa230b78874d150b6a906d48d1d735bd8cb2f2a6ee2faeb343a9c309b3b66106d99dc2f0b65c7e5cbc7511c2e929bf3dee196753b8f12d60681736faecef8daec80f706a15e4d394a7c44038d534dfcdfa5e57d8384ab215f1812608336854b31997f80808d2bfa16073127d1edb75bc4b6bac45af4bfd16e91688922be0cfc1c682042a10ceeadfb3e973ae0012b0f819e2c9f08ff809ae8c807f6be099e82b46ac86bfb9efa55bdb9d5a2b539b161812cb233a81724ff6e9b53bd49259fe6c5a9025b6d1684277b2f4ee45bd3819740a8b8c843338adc812a06d12ab699e8f90751208fa192d33a63f9c2ab85c684abe3fdc528be567e9dce4ab3b3c989d7554e198d4bfe83712a41829d8f10fedfd69686747b79e471adfa5c09a026a8b2f94016c931ac0bb436496c36e2
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58501);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2012/03/27");

  script_name(english:"iTunes Mobile iOS Device Backup Enumeration (Mac OS X)");
  script_summary(english:"Checks for mobile devices being backed up via iTunes");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mac OS X host is used to backup data from a mobile
device.");
  script_set_attribute(attribute:"description", value:
"The iTunes install on the remote Mac OS X host is used by at least
one user to backup data from a mobile iOS device, such as an iPhone,
iPad, or iPod touch.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT1766");
  script_set_attribute(attribute:"solution", value:
"Make sure that backup of mobile devices agrees with your
organization's acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/27");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "macosx_itunes_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");

function parse_device_info(data)
{
  local_var section, value, idx_start, idx_end, datakey;
  local_var device_data, datakeys;

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
    section = '';
    value = NULL;
    # Extract each relevant key/value pair
    idx_start = stridx(data, '<key>'+datakey+'</key>');
    if (datakey == 'Last Backup Date')
      idx_end = stridx(data, '</date>', idx_start);
    else
      idx_end = stridx(data, '</string>', idx_start);
    if ((idx_start >= 0) && (idx_end > idx_start))
    {
      section = substr(data, idx_start, idx_end);
      section = chomp(section);
    }

    # Extract the vale from the key/value pair
    if (strlen(section) > 0)
    {
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
    }
    if (!isnull(value))
    {
      device_data[datakey] = value;
    }
  }
  if (max_index(keys(device_data))) return device_data;
  else return NULL;
}

if (!get_kb_item('Host/local_checks_enabled')) exit(0, 'Local checks are not enabled.');

os = get_kb_item('Host/MacOSX/Version');
if (!os) exit(0, 'The host does not appear to be running Mac OS X.');

if (isnull(get_kb_item('Host/MacOSX/Version'))) exit(0, 'iTunes doesn\'t appear to be installed on the remote host.');

# For each user, look for backups in 
# Library/Application Support/MobileSync/Backup
numdevices = 0;
info = NULL;
cmd = '(echo ; /usr/bin/dscl . -readall /Users NFSHomeDirectory UniqueID) |while read sep; do read Home; read Record; read UniqueID; UniqueID=`echo $UniqueID | awk \'{print $2}\'`; test "$UniqueID" -gt 499 && echo $Record:|awk \'{print $2}\' && Home=`echo $Home|awk \'{print $2}\'` && test -d "$Home"/Library/Application\\ Support/MobileSync/Backup/ && echo "$Home"/Library/Application\\ Support/MobileSync/Backup/*; done';

result = exec_cmd(cmd:cmd);
if (!isnull(result))
{
  lines = split(result, keep:FALSE);
  foreach line (lines)
  {
    devicehash = NULL;
    if ('Library/Application Support/MobileSync' >< line)
    {
      # Replace ' /' with ';/' to make it easier to split up the hashes
      # into a list
      line = str_replace(string:line, find:' /', replace:';/');
      hashlist = split(line, sep:';', keep:FALSE);
      if (!isnull(hashlist))
      {
        for (i=0; i<max_index(hashlist); i++)
        {
          data = NULL;
          plistfile = hashlist[i] + '/Info.plist';
          plistfile = str_replace(string:plistfile, find:'Application Support', replace:'Application\\ Support');
          cmd = 'cat ' + plistfile;

          # Parse the data in the plist file
          data = exec_cmd(cmd:cmd);
          if (!isnull(data) && '<?xml version=' >< data)
          {
            ret = parse_device_info(data:data);

            if (!isnull(ret))
            {
              numdevices++;
              # Build the report
              info += '\n  File path : ' + plistfile;
              info += 
                '\n    Device name      : ' + ret['Device Name'] +
                '\n    Product type     : ' + ret['Product Type'] + 
                '\n    Product version  : ' + ret['Product Version'] + 
                '\n    Serial number    : ' + ret['Serial Number'] +
                '\n    Last backup date : ' + ret['Last Backup Date'] + '\n';
            }
          }
          if (numdevices && !thorough_tests) break;
        }
      }
    }
  }
}

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
      '\n' + a + ' for the following mobile device' + s + ' :\n' +
      info +
      '\n';
    security_note(port:0, extra:report);
  }
  else security_note(0);
  exit(0);
}
else exit(0, 'No backups were detected for mobile iOS devices on the remote host.');
