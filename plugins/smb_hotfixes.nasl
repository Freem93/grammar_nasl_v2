#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(13855);
 script_version("$Revision: 1.84 $");
 script_cvs_date("$Date: 2016/12/14 02:39:41 $");

 script_name(english:"Microsoft Windows Installed Hotfixes");
 script_summary(english:"Fills the KB with the list of installed hotfixes.");

 script_set_attribute(attribute:"synopsis", value:
"It was possible to enumerate installed hotfixes on the remote Windows
host.");
 script_set_attribute(attribute:"description", value:
"Using the supplied credentials, Nessus was able to log into the remote
Windows host, enumerate installed hotfixes, and store them in its
knowledge base for other plugins to use.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/30");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

 script_dependencies("netbios_name_get.nasl", "smb_login.nasl","smb_registry_full_access.nasl", "smb_reg_service_pack.nasl","smb_reg_service_pack_W2K.nasl", "smb_reg_service_pack_XP.nasl");
 script_exclude_keys("SMB/not_windows");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",  "SMB/registry_access");
 script_require_ports(139, 445);
 script_timeout(600);

 exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

if (get_kb_item("SMB/not_windows")) audit(AUDIT_OS_NOT, "Windows");

global_var handle;
global_var Versions;
registry_enumerated = FALSE;

Versions = make_array();

##
# converts a unix timestamp to a human readable date in YYYY/MM/dd format
#
# @anonparam unixtime unix timestamp
# @return human readable date if the conversion succeeded,
#         NULL otherwise
##
function _unixtime_to_date()
{
  local_var unixtime, time, date, month, mday;
  unixtime = _FCT_ANON_ARGS[0];
  if (isnull(unixtime)) return NULL;

  time = localtime(unixtime);
  date = time['year'] + '/';

  month = int(time['mon']);
  if (month < 10)
    date += '0';
  date += time['mon'] + '/';

  mday = int(time['mday']);
  if (mday < 10)
    date += '0';
  date += time['mday'];

  return date;
}

function crawl_for_version(key, level, maxlevel, allow)
{
 local_var mylist, entries, l, list, item, tmp, key_h, info, i, subkey;
 list = make_list();
 entries = make_list();

 if ( level >= maxlevel )
   return make_list();

 if (isnull(allow) || (allow == FALSE))
 {
  tmp = tolower (key);
   if ( "software\classes" >< tmp || "software\wow6432node\classes" >< tmp || "software\clients" >< tmp || "software\microsoft" >< tmp || "software\odbc" >< tmp || "software\policies" >< tmp) return make_list();
 }

 key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
 if(!isnull(key_h))
 {
  info = RegQueryInfoKey(handle:key_h);
  if ( isnull(info) )
  {
   RegCloseKey(handle:key_h);
   return make_list();
  }

  for ( i = 0; i != info[1]; i++ )
  {
   subkey = RegEnumKey(handle:key_h, index:i);
   if ( subkey == NULL ) break;
   else list = make_list(list, key + "\" + subkey);
  }

  item = RegQueryValue(handle:key_h, item:"Version");
  if ( !isnull(item) )
   {
   Versions[key] = item[1];
   }
  RegCloseKey(handle:key_h);
 }

 entries = make_list();
 foreach l (list)
 {
  entries = make_list(entries, crawl_for_version(key:l, level:level + 1, maxlevel:maxlevel, allow:allow));
 }

 return make_list(list, entries);
}

function crawl(key, level, maxlevel)
{
 local_var mylist, entries, l, list, key_h, info, i, subkey;
 list = make_list();
 entries = make_list();

 if ( level >= maxlevel ) return make_list();

 key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
 if(!isnull(key_h))
 {
  info = RegQueryInfoKey(handle:key_h);
  if ( isnull(info) )
  {
   RegCloseKey(handle:key_h);
   return make_list();
  }

  for ( i = 0; i != info[1]; i++ )
  {
   subkey = RegEnumKey(handle:key_h, index:i);
   if ( subkey == NULL ) break;
   else list = make_list(list, key + "\" + subkey);
  }
  RegCloseKey(handle:key_h);
 }

 entries = make_list();
 foreach l (list)
 {
  entries = make_list(entries, crawl(key:l, level:level + 1, maxlevel:maxlevel));
 }

 return make_list(list, entries);
}

function get_key(key, item)
{
 local_var key_h, value;
 key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
 if ( isnull(key_h) ) return NULL;
 value = RegQueryValue(handle:key_h, item:item);
 RegCloseKey(handle:key_h);
 if ( isnull(value) ) return NULL;
 else return value[1];
}

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

port = kb_smb_transport();
login = kb_smb_login();
pass  = kb_smb_password();
domain = kb_smb_domain();

ret = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( ret != 1 ) audit(AUDIT_SHARE_FAIL, 'IPC$');

handle = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(handle) )
{
 set_kb_item(name:"HostLevelChecks/failure", value:"it was not possible to connect to the remote registry");
 NetUseDel ();
 exit(0);
}

vers = get_kb_item("SMB/WindowsVersion");

systemroot = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/SystemRoot");
if(!systemroot)
{
  key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion";
  item = "SystemRoot";
  data = get_key(key:key, item:item);
  if ( data )
  {
    set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/SystemRoot", value:data);
    systemroot = data;
  }
}

access = FALSE;
if ( systemroot )
{
 share = ereg_replace(pattern:"^([A-Za-z]):.*", string:systemroot, replace:"\1$");

 RegCloseKey(handle:handle);
 NetUseDel(close:FALSE);

 r = NetUseAdd(share:share);

 NetUseDel(close:FALSE);
 NetUseAdd(share:"IPC$");

 handle = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
 if ( isnull(handle) )
 {
  set_kb_item(name:"HostLevelChecks/failure", value:"it was not possible to connect to the remote registry");
  NetUseDel ();
  exit(0);
 }

 if (r == 1)  access = TRUE;
}

if (access != TRUE)
{
   report = '
The SMB account used for this test does not have sufficient privileges to get
the list of the hotfixes installed on the remote host. As a result, Nessus was
not able to determine the missing hotfixes on the remote host and most SMB checks
have been disabled.

Solution : Configure the account you are using to get the ability to connect to ADMIN$';
 set_kb_item(name:"HostLevelChecks/failure", value:"the account used does not have sufficient privileges to read all the required registry entries");
   security_note(port:0, extra:report);
   RegCloseKey(handle:handle);
   NetUseDel();
   exit(1);
}

# Make sure it is a 32bits system
arch = '';

key_h = RegOpenKey(handle:handle, key:"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
 item = RegQueryValue(handle:key_h, item:"PROCESSOR_ARCHITECTURE");
 if (!isnull(item))
 {
   arch = item[1];
   if ("64" >< arch) arch = "x64";
   else arch = "x86";

   set_kb_item(name:"SMB/ARCH", value:arch);
 }

 RegCloseKey(handle:key_h);
}

if ("x86" >!< arch && vers !~ "^(1[0-9]|[6-9]\.|5\.2)" )
{
 RegCloseKey(handle:handle);
 NetUseDel();
 exit(1);
}

crawl_for_version(key:"SOFTWARE\Microsoft\Active Setup\Installed Components", level:0, maxlevel:2, allow:TRUE);
foreach k (keys(Versions))
{
 s = str_replace(find:"\", replace:"/", string:k);
 if ( ! isnull(Versions[k]) )
  set_kb_item(name:"SMB/Registry/HKLM/" + s + "/Version", value:Versions[k]);
}

#
# Check for common registry values other plugins are likely to look at
#
key = "SYSTEM\CurrentControlSet\Control\ProductOptions";
item = "ProductType";

value = get_key(key:key, item:item);
if ( value ) set_kb_item(name:"SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Control/ProductOptions", value:value);

key = "SYSTEM\CurrentControlSet\Services\W3SVC";
item = "ImagePath";
value = get_key(key:key, item:item);
if ( value ) set_kb_item(name:"SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/W3SVC/ImagePath", value:value);

key = "SOFTWARE\Microsoft\DataAccess";
item = "Version";
value = get_key(key:key, item:item);
if ( value ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/DataAccess/Version", value:value);

key = "SYSTEM\CurrentControlSet\Control\LSA";
item = "RestrictAnonymous";
data = get_key(key:key, item:item);
if ( !isnull(data) ) set_kb_item(name:"SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Control/LSA/RestrictAnonymous", value:data);

# Exchange detection
#
# - 2010 (14), 2013 (15), and 2016 (15.1)
exchange_found = FALSE;
exchange_versions = make_list("14", "15");
# Needed to support the CU model for 2016, aka 15.1
major = 0;
minor = 0;
foreach version (exchange_versions)
{
  key = "SOFTWARE\Microsoft\ExchangeServer\v" + version + "\Setup";
  item = "MsiInstallPath";
  value = get_key(key:key, item:item);
  if ( value )
  {
    set_kb_item(name:"SMB/Exchange/Path", value:value);

    if (version != "15")
    {
      item = "MsiProductMajor";
      value = get_key(key:key, item:item);
      if ( value )
      {
        value = value*10;
        set_kb_item(name:"SMB/Exchange/Version", value:value);

        item = "MsiProductMinor";
        value = get_key(key:key, item:item);
        if ( value )
        {
         set_kb_item(name:"SMB/Exchange/SP", value:value);
        }
      }
    }
    if (version == "15")
    {
      item = "MsiProductMajor";
      major = get_key(key:key, item:item);
      if ( major )
      {
        major = major * 10;

        item = "MsiProductMinor";
        minor = get_key(key:key, item:item);
        if ( minor )
        {
          major = major + minor;
        }

        set_kb_item(name:"SMB/Exchange/Version", value:major);
      }

    }

    exchange_found = TRUE;
    break;
  }
}
# - versions 2007 and older.
if (!exchange_found)
{
  key = "SOFTWARE\Microsoft\Exchange\Setup";
  item = "Services";
  value = get_key(key:key, item:item);
  if ( value )
  {
   set_kb_item(name:"SMB/Exchange/Path", value:value);

   item = "Services Version";
   value = get_key(key:key, item:item);
   if ( value )
   {
    set_kb_item(name:"SMB/Exchange/Version", value:value);

    item = "ServicePackNumber";
    value = get_key(key:key, item:item);
    if ( value )
    {
     set_kb_item(name:"SMB/Exchange/SP", value:value);
    }
   }
   else
   {
    item = "MsiProductMajor";
    value = get_key(key:key, item:item);
    if ( value )
    {
     value = value*10;
     set_kb_item(name:"SMB/Exchange/Version", value:value);

     item = "MsiProductMinor";
     value = get_key(key:key, item:item);
     if ( value )
     {
      set_kb_item(name:"SMB/Exchange/SP", value:value);
     }
    }
   }

   item = "Web Connector";
   value = get_key(key:key, item:item);
   if ( value )
   {
    set_kb_item(name:"SMB/Exchange/OWA", value:TRUE);
   }
  }
}

key = "SYSTEM\CurrentControlSet\Services\DHCPServer";
key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
if ( !isnull(key_h) )
{
 set_kb_item(name:"SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/DHCPServer", value:1);
 RegCloseKey(handle:key_h);
}

key = "SYSTEM\CurrentControlSet\Services\SMTPSVC";
item = "DisplayName";
value = get_key(key:key, item:item);
if ( value ) set_kb_item(name:"SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/SMTPSVC/DisplayName", value:value);

key = "SYSTEM\CurrentControlSet\Services\SNMP";
item = "DisplayName";
value = get_key(key:key, item:item);
if ( value ) set_kb_item(name:"SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/SNMP/DisplayName", value:value);

key = "SYSTEM\CurrentControlSet\Services\WINS";
item = "DisplayName";
data = get_key(key:key, item:item);
if ( data )  set_kb_item(name:"SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/WINS/DisplayName", value:data);

key = "SYSTEM\CurrentControlSet\Services\DNS";
item = "DisplayName";
data = get_key(key:key, item:item);
if ( data )  set_kb_item(name:"SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/DNS/DisplayName", value:data);

key = "SOFTWARE\Microsoft\DirectX";
item = "Version";
data = get_key(key:key, item:item);
if ( data ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/DirectX/Version", value:data);

# Check Visio version
visio_keys = make_array(
  "10.0", "SOFTWARE\Microsoft\Visio\Installer",
  "11.0", "SOFTWARE\Microsoft\Office\11.0\Visio",
  "12.0", "SOFTWARE\Microsoft\Office\12.0\Visio\InstallRoot",
  "14.0", "SOFTWARE\Microsoft\Office\14.0\Visio\InstallRoot",
  "15.0", "SOFTWARE\Microsoft\Office\15.0\Visio\InstallRoot",
  "16.0", "SOFTWARE\Microsoft\Office\16.0\Visio\InstallRoot"
);

visio_items = make_array(
  "10.0", "Visio10InstallLocation",
  "11.0", "CurrentlyRegisteredVersion",
  "12.0", "Path",
  "14.0", "Path",
  "15.0", "Path",
  "16.0", "Path"
);

foreach ver (keys(visio_keys))
{
  key = visio_keys[ver];
  value = get_key(key:key, item:visio_items[ver]);
  if ( value )
  {
    if ('11.0' >< ver)
    {
      visio_path = NULL;
      key = "SOFTWARE\Microsoft\Office\11.0\Common\InstallRoot";
      item = "Path";

      value = get_key(key:key, item:item);
      if ( value )
      {
        if (egrep(pattern:'^.*OFFICE11.*', string:value))
        {
          value = ereg_replace(pattern:'^(.*)OFFICE11.*', string:value, replace:"\1");
        }
        visio_path = value;
      }

      if (isnull(visio_path))
      {
        key = "SOFTWARE\Microsoft\Office\11.0\InfoPath\InstallRoot";
        item = "Path";

        value = get_key(key:key, item:item);
        if ( value )
        {
          if (egrep(pattern:'^.*OFFICE11.*', string:value))
          {
            value = ereg_replace(pattern:'^(.*)OFFICE11.*', string:value, replace:"\1");
          }
          visio_path = value;
        }
      }
      if (!isnull(visio_path))
      {
        set_kb_item(name:"SMB/Office/Visio/11.0/VisioPath", value:visio_path);
        replace_kb_item(name:"SMB/Office/Visio/Installed", value:TRUE);
      }
    }
    else
    {
      set_kb_item(name:"SMB/Office/Visio/"+ver+"/VisioPath", value:value);
      replace_kb_item(name:"SMB/Office/Visio/Installed", value:TRUE);
    }
  }
}

# Check Office products

office_products = make_list("Outlook", "Word", "Excel", "Powerpoint", "Publisher", "Access");

# Grab info about service pack upgrades, if available.
foreach version (OFFICE_MAJOR_VERS)
{
  key = "SOFTWARE\Microsoft\Office\" + version + "\Common\ProductVersion";
  key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
  if ( !isnull(key_h) )
  {
   item = RegQueryValue(handle:key_h, item:"LastProduct");
   if (!isnull(item))
   {
     last_product = item[1];
     set_kb_item(name:"SMB/Office/"+version+"/LastProduct", value:last_product);
   }
   RegCloseKey(handle:key_h);
  }
  # Determine the Bitness of Office
  key = "SOFTWARE\Microsoft\Office\" + version + "\Outlook";
  key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:"Bitness");
    if (!isnull(item))
    {
      bitness = item[1];
      set_kb_item(name:"SMB/Office/"+version+"/Bitness", value:bitness);
    }
    RegCloseKey(handle:key_h);
  }
}

foreach product (office_products)
{
 foreach version (OFFICE_MAJOR_VERS)
 {
  key = "SOFTWARE\Microsoft\Office\" + version + "\" + product + "\InstallRoot";
  key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
  if ( !isnull(key_h) )
  {
   path = RegQueryValue(handle:key_h, item:"Path");
   if (!isnull(path))
   {
     set_kb_item(name:"SMB/Office/"+product+"/"+version+"/Path", value:path[1]);
   }

   RegCloseKey(handle:key_h);
   #break; # -> next product
  }
 }
}

# Check Office Viewers

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{90840409-6000-11D3-8CFE-0150048383C9}";
key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
if ( !isnull(key_h) )
{
 version = RegQueryValue(handle:key_h, item:"DisplayVersion");
 if (!isnull(version))
 {
  version = ereg_replace(pattern:"^([0-9]+\.[0-9]+)\..*", string:version[1], replace:"\1");
  path = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(path))
    set_kb_item(name:"SMB/Office/ExcelViewer/"+version+"/Path", value:path[1]);

  RegCloseKey(handle:key_h);
 }
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{90850409-6000-11D3-8CFE-0150048383C9}";
key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
if ( !isnull(key_h) )
{
 version = RegQueryValue(handle:key_h, item:"DisplayVersion");
 if (!isnull(version))
 {
  version = ereg_replace(pattern:"^([0-9]+\.[0-9]+)\..*", string:version[1], replace:"\1");
  path = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(path))
    set_kb_item(name:"SMB/Office/WordViewer/"+version+"/Path", value:path[1]);

  RegCloseKey(handle:key_h);
 }
}

key = "SOFTWARE\Microsoft\Internet Explorer";
item = "svcVersion";
data = get_key(key:key, item:item);
if (!data)
{
  item = "Version";
  data = get_key(key:key, item:item);
}
if ( data ) set_kb_item(name:"SMB/IE/Version", value:data);

key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
item = "Shell";
data = get_key(key:key, item:item);
if ( data ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion/Winlogon/Shell", value:data);

data = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/ProgramFilesDir");
if (!data)
{
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion";
  item = "ProgramFilesDir";
  data = get_key(key:key, item:item);
  if ( data ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/ProgramFilesDir", value:data);
}

data = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/ProgramFilesDirx86");
if (!data)
{
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion";
  item = "ProgramFilesDir (x86)";
  data = get_key(key:key, item:item);
  if ( data ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/ProgramFilesDirx86", value:data);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion";
item = "CommonFilesDir";
data = get_key(key:key, item:item);
if ( data ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/CommonFilesDir", value:data);

key = "SOFTWARE\Microsoft\Windows\CurrentVersion";
item = "CommonFilesDir (x86)";
data = get_key(key:key, item:item);
if ( data ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/CommonFilesDirx86", value:data);

key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
item = "ProgramData";
data = get_key(key:key, item:item);
if ( data ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows NT/CurrentVersion/ProfileList/ProgramData", value:data);

# Works detection.
key = "SOFTWARE\Microsoft\Works";
key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  version = NULL;
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ "^[0-9.]+$")
    {
      key2 = key + "\" + subkey;
      key2_h = RegOpenKey(handle:handle, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        value = RegQueryValue(handle:key2_h, item:"CurrentVersion");
        if (!isnull(value))
        {
          version = value[1];
          set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Works", value:TRUE);
          set_kb_item(name:"SMB/Works/Version", value:version);
        }
        RegCloseKey(handle:key2_h);
      }
    }
    if (!isnull(version)) break;
  }
  RegCloseKey(handle:key_h);
}

# Windows 2012 / 2012 R2 / 2016 / 2016 R2 Server Core Detection
#  ServerCore is always present and set to 1 even in the full server install.
#  Both Server-Gui-Mgmt and Server-Gui-Shell are optional and may not be present.
#  If all 3 are present then Server Core is not configured, but the full server.
#  Reference: https://msdn.microsoft.com/en-us/library/hh846315(v=vs.85).aspx

productname = get_kb_item("SMB/ProductName");
if (!isnull(productname) && (("Server 2012" >< productname) || ("Server 2016" >< productname)))
{
  key   = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Server\ServerLevels";
  items = make_list("ServerCore", "Server-Gui-Mgmt", "Server-Gui-Shell");

  i = 0;
  foreach item (items)
  {
    data = get_key(key:key, item:item);
    if (isnull(data)) break;
    i++;
  }

  if (i < 3) set_kb_item(name:"SMB/ServerCore", value:TRUE);
  else       set_kb_item(name:"SMB/ServerCore", value:FALSE);
}

key = "SOFTWARE\Microsoft\Fpc";
item = "InstallDirectory";
data = get_key(key:key, item:item);
if ( data ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Fpc", value:data);

key = "SOFTWARE\Microsoft\Active Setup\Installed Components\{6BF52A52-394A-11d3-B153-00C04F79FAA6}";
item = "IsInstalled";
data = get_key(key:key, item:item);
if ( data )
{
 item = "Version";
 data = get_key(key:key, item:item);
 if ( data ) set_kb_item(name:"SMB/WindowsMediaPlayer", value:data);
}

key = "SOFTWARE\Microsoft\MediaPlayer";
item = "Installation Directory";
data = get_key(key:key, item:item);
if ( data )
{
 set_kb_item(name:"SMB/WindowsMediaPlayer_path", value:data);
}

key = "SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\5.0";
item = "Location";
data = get_key(key:key, item:item);
if ( data )
{
 set_kb_item(name:"Frontpage/2002/path", value:data);
}

key = "SOFTWARE\Microsoft\Internet Explorer";
item = "Version";
data = get_key(key:key, item:item);
if ( data ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Internet Explorer/Version", value:data);

key = "SOFTWARE\Microsoft\Internet Explorer\Version Vector";
item = "IE";
data = get_key(key:key, item:item);
if ( data ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Internet Explorer/Version Vector/IE", value:data);

key =  "SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings";
item = "MinorVersion";
data = get_key(key:key, item:item);
if ( data ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Internet Settings/MinorVersion", value:data);

key  = "SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\{03D9F3F2-B0E3-11D2-B081-006008039BF0}";
item = "Compatibility Flags";
data = get_key(key:key, item:item);
if ( data ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Internet Explorer/ActiveX Compatibility/{03D9F3F2-B0E3-11D2-B081-006008039BF0}", value:data);

key  = "SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\{00000566-0000-0010-8000-00AA006D2EA4}";
item = "Compatibility Flags";
data = get_key(key:key, item:item);
if ( data ) set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Internet Explorer/ActiveX Compatibility/{00000566-0000-0010-8000-00AA006D2EA4}/Compatibility Flags", value:data);

key = "SOFTWARE\Microsoft\MSSQLServer\SQLServerAgent\SubSystems";
item = "CmdExec";
data = get_key(key:key, item:item);
if ( data )
{
 path =  ereg_replace(pattern:"^([A-Za-z]:.*)\\sqlcmdss\.(DLL|dll).*", replace:"\1", string:data);
 if ( path ) set_kb_item (name:"MSSQL/Path", value:path);
}

set_kb_item(name:"SMB/Registry/Enumerated", value:TRUE);
registry_enumerated = TRUE;

#
# Check for Uninstall
#

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
if(!isnull(key_h))
{
 info = RegQueryInfoKey(handle:key_h);
 if (!isnull(info))
 {
  for (i=0; i<info[1]; i++)
  {
   subkey = RegEnumKey(handle:key_h, index:i);

   key_h2 = RegOpenKey(handle:handle, key:key+"\"+subkey, mode:MAXIMUM_ALLOWED);
   if (!isnull (key_h2))
   {
    value = RegQueryValue(handle:key_h2, item:"DisplayName");
    if (!isnull (value))
    {
      name = key + "\" + subkey + "\DisplayName";
      name = str_replace(find:"\", replace:"/", string:name);
      name = "SMB/Registry/HKLM/" + name;
      if ( ! isnull(value[1]) )
       set_kb_item (name:name, value:value[1]);
    }

    value = RegQueryValue(handle:key_h2, item:"DisplayVersion");
    if (!isnull (value) && ! isnull(value[1]) )
    {
      name = key + "\" + subkey + "\DisplayVersion";
      name = str_replace(find:"\", replace:"/", string:name);
      name = "SMB/Registry/HKLM/" + name;
      if ( ! isnull(value[1]) )
       set_kb_item (name:name, value:value[1]);
    }

    value = RegQueryValue(handle:key_h2, item:"InstallDate");
    if (!isnull (value))
    {
      name = key + "\" + subkey + "\InstallDate";
      name = str_replace(find:"\", replace:"/", string:name);
      name = "SMB/Registry/HKLM/" + name;

      # the date can be in any format. if it's YYYYMMdd, reformat it to make it slightly more readable
      if ( value[1] =~ "^\d{8}$" ) # YYYYMMdd
        date = substr(value[1], 0, 3) + '/' + substr(value[1], 4, 5) + '/' + substr(value[1], 6);
      else if ( value[1] =~ "^\d{10}$" ) # formatted like a unix timestamp
      {
        date = _unixtime_to_date(value[1]);

        # if the conversion fails, the date will be saved as whatever value was pulled from the registry
        if (isnull(date)) date = value[1];
      }
      else
        date = value[1];

      if ( !isnull(name) && !isnull(date) ) set_kb_item (name:name, value:date);
    }

    value = RegQueryValue(handle:key_h2, item:"InstallLocation");
    if (!isnull (value) && ! isnull(value[1]) )
    {
      name = key + "\" + subkey + "\InstallLocation";
      name = str_replace(find:"\", replace:"/", string:name);
      name = "SMB/Registry/HKLM/" + name;
      if ( ! isnull(value[1]) )
       set_kb_item (name:name, value:value[1]);
    }

    RegCloseKey (handle:key_h2);
   }
  }
 }
 RegCloseKey(handle:key_h);
}

if ( arch == "x64" )
{
key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall";
key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED, wow:FALSE);
if(!isnull(key_h))
{
 info = RegQueryInfoKey(handle:key_h);
 if ( !isnull(info) )
 {
  for ( i = 0; i != info[1]; i++ )
  {
   subkey = RegEnumKey(handle:key_h, index:i);

   key_h2 = RegOpenKey(handle:handle, key:key+"\"+subkey, mode:MAXIMUM_ALLOWED, wow:FALSE);
   if (!isnull (key_h2))
   {
    value = RegQueryValue(handle:key_h2, item:"DisplayName");
    if (!isnull (value))
    {
      name = key + "\" + subkey + "\DisplayName";
      name = str_replace(find:"\", replace:"/", string:name);
      name = "SMB/Registry/HKLM/" + name;
      name -= "Wow6432Node/";
      if ( ! isnull(value[1]) )
       set_kb_item (name:name, value:value[1]);
    }

    value = RegQueryValue(handle:key_h2, item:"DisplayVersion");
    if (!isnull (value) && ! isnull(value[1]) )
    {
      name = key + "\" + subkey + "\DisplayVersion";
      name = str_replace(find:"\", replace:"/", string:name);
      name = "SMB/Registry/HKLM/" + name;
      name -= "Wow6432Node/";
      if ( ! isnull(value[1]) )
       set_kb_item (name:name, value:value[1]);
    }

    value = RegQueryValue(handle:key_h2, item:"InstallDate");
    if (!isnull (value))
    {
      name = key + "\" + subkey + "\InstallDate";
      name = str_replace(find:"\", replace:"/", string:name);
      name = "SMB/Registry/HKLM/" + name;
      name -= "Wow6432Node/";
      if ( value[1] =~ "^\d{8}$" ) # YYYYMMdd
      {
        # save the date in the KB so it's slightly more user friendly
        date = substr(value[1], 0, 3) + '/' + substr(value[1], 4, 5) + '/' + substr(value[1], 6);
        set_kb_item (name:name, value:date);
      }
    }

    value = RegQueryValue(handle:key_h2, item:"InstallLocation");
    if (!isnull (value) && ! isnull(value[1]) )
    {
      name = key + "\" + subkey + "\InstallLocation";
      name = str_replace(find:"\", replace:"/", string:name);
      name = "SMB/Registry/HKLM/" + name;
      name -= "Wow6432Node/";
      if ( ! isnull(value[1]) )
       set_kb_item (name:name, value:value[1]);
    }

    RegCloseKey (handle:key_h2);
   }
  }
 }
 RegCloseKey(handle:key_h);
 }
}
set_kb_item(name:"SMB/Registry/Uninstall/Enumerated", value:TRUE);

RegCloseKey(handle:handle);
NetUseDel(close:FALSE);

hcf_init = 1;
if (is_accessible_share())
{
  if (registry_enumerated && defined_func('report_xml_tag'))
    report_xml_tag(tag:"Credentialed_Scan", value:"true");

  file = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:systemroot + "\system32\prodspec.ini");
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:systemroot);

  ret = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if ( ret != 1 ) exit(0);

  handle = CreateFile(
    file:file,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  if ( ! isnull(handle) )
  {
    resp = ReadFile(handle:handle, length:16384, offset:0);
    CloseFile(handle:handle);
    resp =  str_replace(find:'\r', replace:'', string:resp);
    set_kb_item(name:"SMB/ProdSpec", value:resp);
  }
  NetUseDel(close:TRUE);
}
