#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35730);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/11 15:07:34 $");

  script_name(english:"Microsoft Windows USB Device Usage Report");
  script_summary(english:"Checks for historic USB device usage.");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to get a list of USB devices that may have been
connected to the remote system in the past.");
  script_set_attribute(attribute:"description", value:
"Using the supplied credentials, this plugin enumerates USB devices
that have been connected to the remote Windows host in the past.");
  script_set_attribute(attribute:"see_also", value:"http://www.forensicswiki.org/wiki/USB_History_Viewing");
  script_set_attribute(attribute:"solution", value:
"Make sure that the use of USB drives is in accordance with your
organization's security policy.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl","smb_reg_service_pack.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("datetime.inc");
include("smb_func.inc");

vista_or_later = 0;

version = get_kb_item("SMB/WindowsVersion");
if(!isnull(version))
{
  v = split(version, sep:".",keep:FALSE);
  if(v[0] && int(v[0]) >= 6)
  vista_or_later = 1;
}

port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
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

device = NULL;
devices = make_list();
hwids   = make_list();

key = "SYSTEM\CurrentControlSet\Enum\USBSTOR";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; i++)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey))
    {
      key2 = key + "\" + subkey;
      key_h2 = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);

      if(!isnull(key_h2))
      {
        info2 =  RegQueryInfoKey(handle:key_h2);
        for(j=0 ; j< info2[1] ; j++)
        {
          subkey2 = RegEnumKey(handle:key_h2, index:j);
          if (strlen(subkey2))
          {
            key3 = key2 + "\" + subkey2 ;
            key_h3 = RegOpenKey(handle:hklm, key:key3, mode:MAXIMUM_ALLOWED);
            if (!isnull(key_h3))
            {
              value = RegQueryValue(handle:key_h3, item:"HardwareID");
              if(!isnull(value))
              {
                hid = value[1];
                hid = tolower(hid);
                hid = str_replace(find:'\0', replace:'.', string:hid);
                device = "HardwareID : " + hid + '##\n';

                 if(vista_or_later)
                {
                  # For vista or later we do not rely on 'hid' to extract the
                  # time associated with device install. Its easier to match
                  # device install time with id extracted from 'key3' instead.

                  hid = ereg_replace(pattern:"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\(.+)",string:key3,replace:"\1");
                  hid = tolower(hid);
                  device = "HardwareID : " + hid + '##\n';
                }

                 hwids = make_list(hwids,hid);
              }

              value = RegQueryValue(handle:key_h3, item:"FriendlyName");
              if(!isnull(value))
              {
                name = value[1];
                device += "Device Name : " + name + '\n';
              }

              value = RegQueryValue(handle:key_h3, item:"Class");
              if(!isnull(value))
              {
                class = value[1];
                device += "Class : " + class + '\n';
              }

              last_write_time = get_last_write_time(serial: subkey2, hklm: hklm);
              if (!isnull(last_write_time))
              {
                device += "Last Inserted Time : " + last_write_time + '\n';
              }
              else
              {
                device += 'Last Inserted Time : unknown\n';
              }
              devices = make_list(devices, device + '\n');

              RegCloseKey(handle:key_h3);
            }
          }
        }

        RegCloseKey(handle:key_h2) ;
      }
    }
  }
  RegCloseKey(handle:key_h) ;
}

key = "SYSTEM\CurrentControlSet\Enum\USB";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; i++)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey))
    {
      key2 = key + "\" + subkey;
      key_h2 = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);

      if(!isnull(key_h2))
      {
        info2 =  RegQueryInfoKey(handle:key_h2);
        for(j=0 ; j< info2[1] ; j++)
        {
          subkey2 = RegEnumKey(handle:key_h2, index:j);
          if (strlen(subkey2))
          {
            key3 = key2 + "\" + subkey2 ;
            key_h3 = RegOpenKey(handle:hklm, key:key3, mode:MAXIMUM_ALLOWED);
            if (!isnull(key_h3))
            {
              value = RegQueryValue(handle:key_h3, item:"HardwareID");
              if(!isnull(value))
              {
                hid = value[1];
                hid = str_replace(find:'\0', replace:'.', string:hid);
                set_kb_item(name:"SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Enum/USB/"+subkey+"/"+subkey2+"/HardwareID", value:hid);
                replace_kb_item(name:"Host/EnumUSB", value:TRUE);
              }

              value = RegQueryValue(handle:key_h3, item:"LocationInformation");
              if(!isnull(value))
              {
                location_information = value[1];
                set_kb_item(name:"SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Enum/USB/"+subkey+"/"+subkey2+"/LocationInformation", value:location_information);
              }

              RegCloseKey(handle:key_h3);
            }
          }
        }
        RegCloseKey(handle:key_h2);
      }
    }
  }
  RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);

NetUseDel(close:FALSE);

# Exit if we don't find any USB devices.

if(isnull(device))
{
  NetUseDel();
  exit(0);
}

hash = make_array();

path = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/SystemRoot");
if(!isnull(path))
{
  share   = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);

  # Get the last connected times from setupapi.log/setupapi.dev.log
  #
  # For Vista and later, setupapi.log can be found under
  # c:\Windows\inf\setupapi.dev.log
  #
  # http://msdn.microsoft.com/en-us/library/aa477110.aspx

  if(vista_or_later)
    logfile = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\inf\setupapi.dev.log", string:path);
  else
    logfile = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\setupapi.log", string:path);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL,share);
  }

  fh = CreateFile(
    file               : logfile,
    desired_access     : GENERIC_READ,
    file_attributes    : FILE_ATTRIBUTE_NORMAL,
    share_mode         : FILE_SHARE_READ,
    create_disposition : OPEN_EXISTING
  );

  if (!isnull(fh))
  {
    fsize = GetFileSize(handle:fh);
    if (fsize > 0)
    {
      # Read the entire file only if thorough_tests is enabled.
      chunks = int(fsize/10240);
      if(!thorough_tests && chunks > 10 ) chunks = 10;

      offset = 0;
      count = 0;
      # Read the file in chunks
      while (count < chunks && offset < fsize)
      {
        data = ReadFile(handle:fh, length:10240, offset:offset);
        lines = split(data, sep:'\r\n', keep:FALSE);
        foreach line (lines)
        {
          if(vista_or_later)
          {
            # We first get the id first and then the time.

            if (ereg(pattern:">>> *\[Device Install \(Hardware initiated\) - USBSTOR\\",string:line))
            {
              match = eregmatch(pattern:">>> *\[Device Install \(Hardware initiated\) - USBSTOR\\(.+)\]",string:line);
              if(!isnull(match[1]))
              {
                hid = tolower(match[1]);
                flag = 1;
              }
            }
            if(flag && ereg(pattern:">>>  Section start [0-9]+/[0-9]+/[0-9]+ [0-9]+:[0-9]+:[0-9]+\.[0-9]+$",string:line))
            {
              match = eregmatch(pattern:">>>  Section start ([0-9]+/[0-9]+/[0-9]+ [0-9]+:[0-9]+:[0-9]+\.[0-9]+)$",string:line);
              hash[hid] = match[1];
              flag = 0;
            }
          }
          else
          {
            if (ereg(pattern:"Driver Install",string:line))
            {
              time = NULL;
              match = eregmatch(pattern:"^\[([0-9]+/[0-9]+/[0-9]+ [0-9]+:[0-9]+:[0-9]+) [0-9]+.[0-9]+ Driver Install\]$",string:line);
              if(!isnull(match[1]))
              {
                time = match[1];
                flag = 1;
              }
            }
            if (flag && ereg(pattern:"Searching for hardware ID\(s\): usb",string:line))
            {
              hid = NULL;
              hid = ereg_replace(pattern:"#.+ Searching for hardware ID\(s\): (.+)$",string:line,replace:"\1");
              hid = str_replace(string:hid,find:",",replace:".");
              hash[hid] = time;
              flag = 0;
            }
          }
        }
        offset += 10240;
        count++;
      }
    }
    CloseFile(handle:fh);
  }
  NetUseDel();
}

# Now Report.

report = NULL;
if (!isnull(devices))
{
  for (i = 0 ; i < max_index(devices); i++)
  {
    d = devices[i];
    found = 0;

    foreach k (keys(hash))
    {
      if ( k >< d)
      {
        found = 1;
        # Get rid of hardware id, as it makes report clumsier
        d = ereg_replace(pattern:"HardwareID.+##(.+)",string:d, replace:"\1");
        d = d + "First used : " + hash[k] + '\n';
        report += d;
      }
    }
    if (!found)
    {
      # Get rid of hardware id, as it makes report clumsier
      d = ereg_replace(pattern:"HardwareID.+##(.+)",string:d, replace:"\1");
      d = d + "First used : unknown" + '\n';
      report += d;
    }
  }
}

if(!isnull(report))
{
  report =
    '\n' +
    'The following is a list of USB devices that have been connected\n' +
    'to remote system at least once in the past :\n' +
    '\n' +
    report + '\n';

  if (!thorough_tests)
    report =
      report +
      '(Note that for a complete listing of \'First used\' times you should\n' +
      'run this test with the option \'thorough_tests\' enabled.)\n';

  security_note(port:port, extra:report);
}

function get_last_write_time(serial, hklm)
{
  if (isnull(serial)) return NULL;

  local_var key, key_h, info, i, subkey, key2, key_h2, info2, last_write_time;
  local_var subkey2, key_h3, key3, info3, k;
  key = "SYSTEM\CurrentControlSet\Enum\USB";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    info = RegQueryInfoKey(handle:key_h);
    for (i=0; i<info[1]; i++)
    {
      subkey = RegEnumKey(handle:key_h, index:i);
      if (strlen(subkey))
      {
        key2 = key + "\" + subkey;
        key_h2 = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);

        if(!isnull(key_h2))
        {
          info2 = RegQueryInfoKey(handle:key_h2);
          for (k=0; k<info2[1]; k++)
          {
            subkey2 = RegEnumKey(handle:key_h2, index:k);
            if (strlen(subkey2) && (subkey2 >< serial))
            {
              key3 = key2 + "\" + subkey2;
              key_h3 = RegOpenKey(handle:hklm, key:key3, mode:MAXIMUM_ALLOWED);

              if(!isnull(key_h3))
              {
                info3 =  get_key_timestamp(handle:key_h3);
                if (!isnull(info3))
                {
                  last_write_time = strftime("%N", info3);
                }
                RegCloseKey(handle:key_h3);
                break;
              }
            }
          }
          RegCloseKey(handle:key_h2);
        }
      }
      if (!isnull(last_write_time)) break;
    }
    RegCloseKey(handle:key_h);
  }
  return last_write_time;
}

# Largely a copy of RegQueryInfoKey, but returns the timestamp
# which is not returned from the standard function.
function get_key_timestamp(handle)
{
 local_var data, resp, rep, ret;

 data = handle[0]          +  # Handle
        raw_word (w:0)     +  # Length
	      raw_word (w:0)     +  # Size
	      raw_dword (d:0);      # NULL 
 
 data = dce_rpc_pipe_request (fid:handle[1], code:OPNUM_QUERYINFOKEY, data:data);
 if (!data)
   return NULL;

 # response structure :
 # Class (bad parsed here)
 # num subkeys
 # max subkey len
 # reserved
 # num value
 # max value len
 # max valbuf size
 # secdesc len
 # mod time
 
 rep = dce_rpc_parse_response (fid:handle[1], data:data);
 if (!rep || (strlen (rep) != 48))
   return NULL;

 resp = get_dword (blob:rep, pos:44);
 if (resp != STATUS_SUCCESS)
   return NULL;

 ret = NULL;
 ret = convert_win64_time_to_unixtime(low: get_dword(blob:rep, pos:36), high: get_dword(blob:rep, pos:40));
 return ret;
}
