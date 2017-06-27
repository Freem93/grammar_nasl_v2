#%NASL_MIN_LEVEL 5200
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66350);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/12 17:12:47 $");

  script_name(english:"Microsoft Windows Wireless Network History");
  script_summary(english:"Checks for Historic Wireless Networks the Computer has Connected to.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin identifies wireless networks that the computer has
connected to.");
  script_set_attribute(attribute:"description", value:
"Using the supplied credentials, this plugin reports wireless networks
that this computer has connected to as well as the settings for
Windows Vista and later systems.");
  # http://blogs.technet.com/b/networking/archive/2010/09/08/network-location-awareness-nla-and-how-it-relates-to-windows-firewall-profiles.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7a21f7c2");
  script_set_attribute(attribute:"solution", value:
"Make sure that use of the reported networks agrees with your
organization's acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "smb_reg_service_pack.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_reg_query.inc");
include("smb_file_funcs.inc");
include("http_func.inc");
include("buffer_stream.inc");
include("xml_sax_parser.inc");
include("byte_func.inc");

xmlarrfs = make_array();

##
# format the date from the reg into readable
# output
#
# @param [data:string] the unformated timestamp
# @param [raw_array:bool] output to array if true
#
# @return string format of date,
#    array with the content of the date,
#    NULL if error
##
function format_date(data, raw_array)
{
  local_var timestamp, i, temp, hval, tmap, timestamp_map,
   enum_weekday, period;

  if (strlen(data) < 32) return NULL;

  enum_weekday = make_list("Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday");

  for (i=0;i<32;i+=4)
  {
    hval = (data[i+2]+data[i+3]) + (data[i]+data[i+1]);
    temp = hex2dec(xvalue:hval);
    if (temp > 9 )
      tmap += temp + " ";
    else
      tmap += "0" + temp + " ";
  }

  timestamp_map = split(tmap, sep:' ', keep:FALSE);
  if (isnull(raw_array))
  {
    if (int(timestamp_map[4]) > 12)
    {
      timestamp_map[4] = int(timestamp_map[4]) - 12;
      period = "PM";
      if (int(timestamp_map[4]) < 10)
        timestamp_map[4] = "0" + timestamp_map[4];

    }
    else
      period = "AM";

    # format output
    timestamp = enum_weekday[int(timestamp_map[2])] + ", "; # weekday
    timestamp += timestamp_map[1];  # month
    timestamp += "/"+timestamp_map[3];  # day
    timestamp += "/"+timestamp_map[0];  # year
    timestamp += " ";  # sep
    timestamp += timestamp_map[4]; # hour
    timestamp += ":"+timestamp_map[5]; # minute
    timestamp += ":"+timestamp_map[6]; # sec
    timestamp += "."+timestamp_map[7]; # ms
    timestamp += " "+period;
    return timestamp;
  }

  return timestamp_map;
}

###
# validate the input from a table
# and return a valid string
#
# @param [data:string] string to validate
#
# @return string, modified value with type or
#   the value if it is valid
##
function validate_input(data)
{
  if (isnull(data))
    return "NULL";
  else if (strlen(data) == 0 && (typeof(data) == "string" || typeof(data) == 'data') )
    return "Empty Value";

  return data;
}

##
# Callback for SAX parser
##
function SAX_parse_wireless_network_data(currentTag,name_space,attributesAndValue,currentContent,currentClosing,tagStack,currentComment,type)
{
  if (type == SAXTYPE_CHARDATA)
    xmlarrfs[currentTag] = currentContent;

  return 0;
}

##
# get wireless info from the registry for
# vista+ systems
#
# @return array of date with source key being the ssid,
#      NULL if error
##
function get_wireless_networks_reg()
{
  local_var hklm, networkProfiles, reg_content, networkGUID, managedProfiles,
   managedNetworks, managedID, rval, unmanagedProfiles, unmanagedNetworks,
   unmanagedID, ret, key, ssid;

  registry_init();
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

  ###
  ## get networks profiles
  ###
  networkProfiles = get_registry_subkeys(handle:hklm, key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles");
  if (isnull(networkProfiles))
    audit(AUDIT_REG_FAIL);

  reg_content = make_array();
  foreach networkGUID (networkProfiles)
  {
    reg_content[networkGUID] = get_reg_name_value_table(handle:hklm, key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\\"+networkGUID);
  }
  if (isnull(reg_content))
    audit(AUDIT_REG_FAIL);

  ###
  ## Managed
  ###
  managedProfiles = get_registry_subkeys(handle:hklm, key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed");
  if (isnull(managedProfiles))
    audit(AUDIT_REG_FAIL);

  managedNetworks = make_array();
  foreach managedID (managedProfiles)
  {
    managedNetworks[managedID] = get_reg_name_value_table(handle:hklm, key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed\\"+managedID);
    if (isnull(managedNetworks[managedID]["profileguid"])) continue;

    foreach rval (keys(managedNetworks[managedID]))
    {
      reg_content[managedNetworks[managedID]["profileguid"]][rval] = managedNetworks[managedID][rval];
    }
  }

  ###
  ## unManaged
  ###
  unmanagedProfiles = get_registry_subkeys(handle:hklm, key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged");
  if (isnull(unmanagedProfiles))
    audit(AUDIT_REG_FAIL);

  unmanagedNetworks = make_array();
  foreach unmanagedID (unmanagedProfiles)
  {
    unmanagedNetworks[unmanagedID] = get_reg_name_value_table(handle:hklm, key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged\\"+unmanagedID);
    if (isnull(unmanagedNetworks[unmanagedID]["profileguid"])) continue;

    foreach rval (keys(unmanagedNetworks[unmanagedID]))
    {
      reg_content[unmanagedNetworks[unmanagedID]["profileguid"]][rval] = unmanagedNetworks[unmanagedID][rval];
    }
  }
  RegCloseKey(handle:hklm);
  close_registry();

  ##
  # format content to use ssid as the array key
  ##
  ret = make_array();
  foreach key (keys(reg_content))
  {
    ssid = reg_content[key]["profilename"];
    if (isnull(ssid) || strlen(ssid) == 0)
      continue;

    ret[ssid] = reg_content[key];
    ret[ssid]["guid"] =  key;
    ret[ssid]["managed"] =   validate_input(data:reg_content[key]["managed"]);
    ret[ssid]["description"] = validate_input(data:reg_content[key]["description"]);
    ret[ssid]["ssid"] = validate_input(data:reg_content[key]["profilename"]);
    ret[ssid]["datecreated"] = format_date(data:hexstr(validate_input(data:reg_content[key]["datecreated"])));
    ret[ssid]["datelastconnected"] = format_date(data:hexstr(validate_input(data:reg_content[key]["datelastconnected"])));
    ret[ssid]["category"] = validate_input(data:reg_content[key]["category"]);
    ret[ssid]["description"] = validate_input(data:reg_content[key]["description"]);
    ret[ssid]["defaultgatewaymac"] = hexstr(validate_input(data:reg_content[key]["defaultgatewaymac"]));
    ret[ssid]["firstnetwork"] = validate_input(data:reg_content[key]["firstnetwork"]);
    ret[ssid]["source"] = validate_input(data:reg_content[key]["source"]);
    ret[ssid]["dnssuffix"] = validate_input(data:reg_content[key]["dnssuffix"]);
  }

  return ret;
}

##
# Read in wireless network info from
# the file system. This primarily
# contains the security settings.
#
# @return array of wireless content SSID is key,
#      NULL if error
##
function get_wireless_networks_fs()
{
  local_var system_root, smb_share, dir_path, smb_port, smb_name,
    smb_username, smb_password, smb_domain, soc, rc, dh, root_dir,
    interface_path, file_content, content_index, iPath, iFile, fh,
    fsize, xml, sax_check;

  system_root = hotfix_get_systemroot();
  dir_path = "\\ProgramData\\Microsoft\\Wlansvc\\Profiles\\Interfaces\\*";
  smb_share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:system_root);

  smb_port = kb_smb_transport();
  smb_username = kb_smb_login();
  smb_password = kb_smb_password();
  smb_domain = kb_smb_domain();

  if(! smb_session_init()) return NULL;

  rc = NetUseAdd(login:smb_username, password:smb_password, domain:smb_domain, share:smb_share);
  if (isnull(rc)) return NULL;

  root_dir = ereg_replace(string:dir_path, pattern:"[*]", replace:"");
  interface_path = make_list();
  for (
    dh = FindFirstFile(pattern:root_dir + "*");
    !isnull(dh);
    dh = FindNextFile(handle:dh)
  )
  {
    # Skip non-directories.
    if (dh[2] & FILE_ATTRIBUTE_DIRECTORY == 0) continue;

    # Skip current and parent directories.
    if (dh[1] == "." || dh[1] == "..") continue;

    interface_path = make_list(dh[1], interface_path);
  }
  if (max_index(interface_path) == 0)
  {
    NetUseDel();
    return NULL;
  }

  file_content = make_array();
  content_index = 0;
  foreach iPath (interface_path)
  {
    for (
      iFile = FindFirstFile(pattern:root_dir + iPath + "\\*");
      !isnull(iFile);
      iFile = FindNextFile(handle:iFile)
    )
    {
      # Skip current and parent directories.
      if (iFile[1] == "." || iFile[1] == "..") continue;

      fh = CreateFile(
        file:root_dir + iPath + "\\" + iFile[1],
        desired_access:GENERIC_READ,
        file_attributes:FILE_ATTRIBUTE_NORMAL,
        share_mode:FILE_SHARE_READ,
        create_disposition:OPEN_EXISTING
      );
      if (isnull(fh)) continue;

      fsize = GetFileSize(handle:fh);
      xml = ReadFile(handle:fh, offset:0, length:fsize);
      CloseFile(handle:fh);
      if (isnull(xml)) continue;

      nsbs_streamInit(type:NSBS_STREAM_STRING, content:xml, block_size:10, id:"WinWirelessNetworks");
      sax_check = SAX_ParseXML(id:"WinWirelessNetworks", SAX_XMLCALLBACK:@SAX_parse_wireless_network_data, exit_on_fail:FALSE);

      if (isnull(xmlarrfs["name"]) || isnull(sax_check)) continue;
      file_content[xmlarrfs["name"]] = xmlarrfs;
      content_index++;

      xmlarrfs = make_array();
    }
  }

  if (content_index == 0)
  {
    NetUseDel();
    return NULL;
  }

  NetUseDel();
  return file_content;
}

if (get_kb_item("SMB/not_windows")) audit(AUDIT_OS_NOT, "Windows");

currentVersion = get_kb_item("SMB/WindowsVersionBuild");
if (isnull(currentVersion))
  exit(0, "Could not get CurrentVersion information from registry.");
else if (int(currentVersion) < 6000 )
  exit(0, "This plugin only reports for Windows Vista or later.");

reg_content = get_wireless_networks_reg();
fs_content = get_wireless_networks_fs();

if (isnull(reg_content) && isnull(fs_content))
  exit(0, "Nessus could not get network information from the system.");
if (max_index(keys(reg_content)) == 0 && max_index(keys(fs_content)) == 0)
  exit(0, "Nessus could not get network information from the system.");

if (!isnull(reg_content))
{
  foreach ntw (keys(reg_content))
  {
    if (reg_content[ntw]["nametype"] == 71)
    {
      report += "SSID : " + ntw + '\n';
      if (reg_content[ntw]["managed"] == 1) managed = "TRUE";
      else managed = "FALSE";
      report += "Managed : "           + managed + '\n';
      report += "Description : "       + reg_content[ntw]["description"] + '\n';
      report += "GUID : "              + reg_content[ntw]["guid"] + '\n';
      report += "DateCreated : "       + reg_content[ntw]["datecreated"] + '\n';
      report += "DateLastConnected : " + reg_content[ntw]["datelastconnected"] + '\n';
      report += "Description : "       + reg_content[ntw]["description"]       + '\n';
      report += "DefaultGatewayMac : " + reg_content[ntw]["defaultgatewaymac"] + '\n';
      report += "DnsSuffix : "         + reg_content[ntw]["dnssuffix"]         + '\n';
      report += "FirstNetwork : "      + reg_content[ntw]["firstnetwork"]      + '\n';
      report += "Source : "            + reg_content[ntw]["source"]            + '\n';
      report += "Category : "          + reg_content[ntw]["category"] + '\n';

      if (!isnull(fs_content[ntw]))
      {
        report += 'Security Mode : ' + validate_input(data:fs_content[ntw]["authentication"]) + '\n';
        report += 'Encryption : ' + validate_input(data:fs_content[ntw]["encryption"]) + '\n';
        report += '1x : ' + validate_input(data:fs_content[ntw]["useOneX"]) + '\n';
        report += 'Key Type : ' + validate_input(data:fs_content[ntw]["keyType"]) + '\n';
        report += 'Key Protected : ' + validate_input(data:fs_content[ntw]["protected"]) + '\n';
        report += 'Key Content : ' + validate_input(data:fs_content[ntw]["keyMaterial"]) + '\n';
        report += 'Connection Mode : ' + validate_input(data:fs_content[ntw]["connectionMode"]) + '\n';
        report += 'Connection Type : ' + validate_input(data:fs_content[ntw]["connectionType"]) + '\n';
        fs_content[ntw] = NULL;
      }
      else
        report += 'Security Settings are not logged on the system.\n';
      report += '\n';
    }
  }
}

if (!isnull(fs_content))
{
  foreach key (keys(fs_content))
  {
    if (isnull(fs_content[key])) continue;
    report += 'SSID : ' + key + '\n';
    report += 'Security Mode : ' + validate_input(data:fs_content[key]["authentication"]) + '\n';
    report += 'Encryption : ' + validate_input(data:fs_content[key]["encryption"]) + '\n';
    report += '1x : ' + validate_input(data:fs_content[key]["useOneX"]) + '\n';
    report += 'Key Type : ' + validate_input(data:fs_content[key]["keyType"]) + '\n';
    report += 'Key Protected : ' + validate_input(data:fs_content[key]["protected"]) + '\n';
    report += 'Key Content : ' + validate_input(data:fs_content[key]["keyMaterial"]) + '\n';
    report += 'Connection Mode : ' + validate_input(data:fs_content[key]["connectionMode"]) + '\n';
    report += 'Connection Type : ' + validate_input(data:fs_content[key]["connectionType"]) + '\n';
    report += '\n';
  }
}

if (strlen(report) > 0)
{
  port = kb_smb_transport();
  if (report_verbosity > 0) security_note(port:port, extra:report);
  else security_note(port);
}

