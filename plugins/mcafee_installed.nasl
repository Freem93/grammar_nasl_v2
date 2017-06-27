#
# (C) Tenable Network Security, Inc.
#
# This script has been rewritten by Tenable Network Security
# Original script was written by Jeff Adams <jeffadams@comcast.net>
#

include("compat.inc");

if (description)
{
 script_id(12107);
 script_version("$Revision: 1.1857 $");
 script_cvs_date("$Date: 2016/09/23 15:57:38 $");

 script_name(english:"McAfee Antivirus Detection and Status");
 script_summary(english:"Checks that the remote host has McAfee Antivirus installed and then makes sure the latest Vdefs are loaded.");

 script_set_attribute(attribute:"synopsis", value:
"An antivirus application is installed on the remote host, but it is
not working properly.");
 script_set_attribute(attribute:"description", value:
"McAfee VirusScan, an antivirus application, is installed on the remote
host. However, there is a problem with the installation; either its
services are not running or its engine and/or virus definitions are
out of date.");
 script_set_attribute(attribute:"solution", value:
"Make sure that updates are working and the associated services are
running.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/03/16");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:virusscan_enterprise");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

 script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_full_access.nasl", "smb_enum_services.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access","SMB/transport");
 script_require_ports(139, 445);

 exit(0);
}

include("audit.inc");
include("antivirus.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

global_var hklm;

#==================================================================#
# Section 1. Utilities                                             #
#==================================================================#


#-------------------------------------------------------------#
# Checks the engine version                                   #
#-------------------------------------------------------------#
function check_engine_version (reg, wow)
{
  local_var key, item, key_h, version, value, value1, wowver, keyw, key_wow;

  key = reg;
  if(wow)
  {
    keyw = ereg_replace(pattern:"^SOFTWARE\\(.*)", string:key, replace:"SOFTWARE\Wow6432Node\\1", icase:TRUE);
    key_wow = RegOpenKey(handle:hklm, key:keyw, mode:MAXIMUM_ALLOWED, wow:wow);
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED, wow:wow);
  }
  else key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  version = NULL;
  wowver = NULL;

  if ( !empty_or_null(key_h) )
  {
   value = RegQueryValue(handle:key_h, item:item);

   if (!empty_or_null(value))
   {
    version = split(value[1], sep:".", keep:FALSE);
    version = int(version[0]) * 1000 + int(version[1]) * 100 + int(version[2]);
   }
   else
   {
     # In version 8.5.0.275, engine version is stored here
     value  = RegQueryValue(handle:key_h, item:"EngineVersionMajor");
     value1 = RegQueryValue(handle:key_h, item:"EngineVersionMinor");

     # In newer versions (v8.5i ++) this is stored in ...
     if(empty_or_null(value))
     value  = RegQueryValue(handle:key_h, item:"EngineVersion32Major");

     # In 64 bit systems it is stored in EngineVersion64Major DKO-22286-986
     if(empty_or_null(value))
       value  = RegQueryValue(handle:key_h, item:"EngineVersion64Major");

     if (empty_or_null(value1) )
	     value1 = RegQueryValue(handle:key_h, item:"EngineVersion32Minor");

     # In 64 bit systems it is stored in EngineVersion64Major DKO-22286-986
     if(empty_or_null(value1))
       value1  = RegQueryValue(handle:key_h, item:"EngineVersion64Minor");

     if (!empty_or_null (value) && !empty_or_null(value1))
      {
        version = join(value[1], value1[1], sep:'.');
      }
   }

   RegCloseKey (handle:key_h);
  }
  if(!empty_or_null(key_wow))
  {
    value = NULL;
    value1 = NULL;
    value  = RegQueryValue(handle:key_wow, item:"EngineVersionMajor");
    value1 = RegQueryValue(handle:key_wow, item:"EngineVersionMinor");

    if(empty_or_null(value)) value  = RegQueryValue(handle:key_wow, item:"EngineVersion32Major");
    if(empty_or_null(value)) value  = RegQueryValue(handle:key_wow, item:"EngineVersion64Major");
    if (empty_or_null(value1)) value1 = RegQueryValue(handle:key_wow, item:"EngineVersion32Minor");
    if(empty_or_null(value1)) value1  = RegQueryValue(handle:key_wow, item:"EngineVersion64Minor");

    if (!empty_or_null(value) && !empty_or_null(value1))
    {
      wowver = join(value[1], value1[1], sep:'.');
    }

    RegCloseKey (handle:key_wow);
  }

  return {'val':version,'wow':wowver};
}


#-------------------------------------------------------------#
# Checks the database version                                 #
#-------------------------------------------------------------#
function check_database_version (reg, wow)
{
  local_var key, item, key_h, value, vers, version, wowver, keyw, key_wow;

  key = reg;
  item = "szVirDefVer";
  vers = NULL;
  wowver = NULL;

  if(wow)
  {
    keyw = ereg_replace(pattern:"^SOFTWARE\\(.*)", string:key, replace:"SOFTWARE\Wow6432Node\\1", icase:TRUE);
    key_wow = RegOpenKey(handle:hklm, key:keyw, mode:MAXIMUM_ALLOWED, wow:wow);
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED, wow:wow);
  }
  else key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

  if ( !empty_or_null(key_h) )
  {
    value = RegQueryValue(handle:key_h, item:item);
    if (empty_or_null(value))
    {
      item = "szDatVersion";
      value = RegQueryValue(handle:key_h, item:item);
    }

    # In v8.5i this can be obtained from here..
    if(empty_or_null(value))
    {
      value = RegQueryValue(handle:key_h, item:"AVDatVersion");
    }
   RegCloseKey (handle:key_h);
  }

  if(wow && !empty_or_null(key_wow))
  {
    wowver = RegQueryValue(handle:key_wow, item:"AVDatVersion");
    if(!empty_or_null(wowver)) wowver = wowver[1];
    RegCloseKey (handle:key_wow);
  }

  if (!empty_or_null(value) )
  {
    vers = value[1];

    if ( "4.0." >< vers)
    {
      version = split(vers, sep:".", keep:FALSE);
      vers = version[2];
    }

  }

  return {'val':vers, 'wow':wowver};
}


#-------------------------------------------------------------#
# Checks the database date                                    #
#-------------------------------------------------------------#
function check_database_date (reg, wow)
{
  local_var key, item, key_h, value, vers, wowver, keyw, key_wow;

  key = reg;
  item = "szVirDefDate";
  wowver = NULL;
  vers = NULL;

  if(wow)
  {
    keyw = ereg_replace(pattern:"^SOFTWARE\\(.*)", string:key, replace:"SOFTWARE\Wow6432Node\\1", icase:TRUE);
    key_wow = RegOpenKey(handle:hklm, key:keyw, mode:MAXIMUM_ALLOWED, wow:wow);
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED, wow:wow);
  }
  else key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

  if ( !empty_or_null(key_h) )
  {
   value = RegQueryValue(handle:key_h, item:item);
   if (empty_or_null(value))
   {
    item = "szDatDate";
    value = RegQueryValue(handle:key_h, item:item);
   }
   # In v8.5i this info is located here ..
    if (empty_or_null(value))
   {
    item = "AVDatDate";
    value = RegQueryValue(handle:key_h, item:item);
   }

   if (!empty_or_null(value)) vers = value[1];
   RegCloseKey (handle:key_h);

  }

  if(wow && !empty_or_null(key_wow))
  {
    wowver = RegQueryValue(handle:key_wow, item:item);
    if(!empty_or_null(wowver)) wowver = wowver[1];
    RegCloseKey (handle:key_wow);
  }

  return {'val':vers,'wow':wowver};
}


#-------------------------------------------------------------#
# Checks item in reg key                                      #
#-------------------------------------------------------------#
function check_item (reg, wow, item)
{
  local_var key, key_h, value, vers, wowver, keyw, key_wow;

  key = reg;
  vers = NULL;
  wowver = NULL;

  if(wow)
  {
    keyw = ereg_replace(pattern:"^SOFTWARE\\(.*)", string:key, replace:"SOFTWARE\Wow6432Node\\1", icase:TRUE);
    key_wow = RegOpenKey(handle:hklm, key:keyw, mode:MAXIMUM_ALLOWED, wow:wow);
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED, wow:wow);
  }
  else key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

  if ( !empty_or_null(key_h) )
  {
    value = RegQueryValue(handle:key_h, item:item);
    RegCloseKey (handle:key_h);

    if (!empty_or_null(value)) vers = value[1];
  }
  
  if ( !empty_or_null(key_wow) )
  {
    wowver = RegQueryValue(handle:key_wow, item:item);
    RegCloseKey (handle:key_wow);
    if (!empty_or_null(wowver)) wowver = wowver[1];
  }

  return {'val':vers,'wow':wowver};
}

#-------------------------------------------------------------#
# Checks version keys                                         #
# If Wow6432Node is different, grab both keys                 #
# To be checked against binary at the end                     #
# Returns: True if versions differ, False if ==               #
#-------------------------------------------------------------#
function check_keys()
{
  local_var key, item, key_item, key_h, ver, wowver, wow;

  key = "SOFTWARE\McAfee\AVEngine";
  ver = NULL;
  wowver = NULL;
  wow = FALSE;

  #32
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED, wow:TRUE);
  if(!empty_or_null(key_h))
  {
    key_item = make_list();
    key_item[0] = RegQueryValue(handle:key_h, item:"EngineVersionMajor");
    key_item[1] = RegQueryValue(handle:key_h, item:"EngineVersionMinor");
    if (!empty_or_null(key_item[0]) && !empty_or_null(key_item[1]))
    {
      if (!empty_or_null(key_item[0][1]) && !empty_or_null(key_item[1][1]))
        ver = join(key_item[0][1],key_item[1][1],sep:'.');
    }
    # If the key is still there but empty, the plugin will assume nulls
    # in future checks are correct. So we give ver a value to set wow = True
    else ver = '0.0';
  }
  RegCloseKey(handle:key_h);

  #WOW
  key = "SOFTWARE\Wow6432Node\McAfee\AVEngine";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED, wow:TRUE);
  if(!empty_or_null(key_h))
  {
    key_item = make_list();
    key_item[0] = RegQueryValue(handle:key_h, item:"EngineVersionMajor");
    key_item[1] = RegQueryValue(handle:key_h, item:"EngineVersionMinor");
    if (!empty_or_null(key_item[0]) && !empty_or_null(key_item[1]))
    {
      if (!empty_or_null(key_item[0][1]) && !empty_or_null(key_item[1][1]))
        wowver = join(key_item[0][1],key_item[1][1],sep:'.');
    } 
  }
  RegCloseKey(handle:key_h);

  # We only care to check separate keys if both keys have values
  # and those values are not equal. 
  if (wowver != ver && !empty_or_null(ver) && !empty_or_null(wowver)) wow = TRUE;
  return wow;
}
#-------------------------------------------------------------#
# Checks for binary /confirms installation keys (v8.5+)       #
# Audits out if no binary found.                              #
# Returns True if only WOW values are valid, else false       #            
#-------------------------------------------------------------#
function check_bin(eng_vers, wow)
{
  local_var key, item, key_h, paths, dll, dll_wow, DAT, DATwow, bin, wownode;
  local_var ver, wowver, key_wow, keyw, dll_ver;

  key = "SOFTWARE\McAfee\AVEngine";
  ver = eng_vers['val'];
  wowver = eng_vers['wow'];
  item = "DAT";
  bin = FALSE;
  wownode = FALSE;
  DAT = NULL;
  DATwow = NULL;

  paths = check_item(reg:key, item:item, wow:wow);
  if(!empty_or_null(paths['val'])) DAT = paths['val'];
  if(!empty_or_null(paths['wow'])) DATwow = paths['wow'];  

  NetUseDel();
  
  dll = DAT + "mcscan32.dll";
  dll_ver = hotfix_get_fversion(path:dll);
  hotfix_handle_error(error_code:dll_ver['error'], file:dll, appname:"McAfee VirusScan");
  dll_ver = dll_ver['value'];
  dll_ver =join(join(dll_ver[0],dll_ver[1],sep:""), dll_ver[3], sep:".");

  if(wow)
  {
    if(DATwow != DAT)
    {
      dll = DATwow + "mcscan32.dll";
      dll_wow = hotfix_get_fversion(path:dll);
      hotfix_handle_error(error_code:dll_wow['error'], file:dll, appname:"McAfee VirusScan", exit_on_fail:TRUE);

      dll_wow = dll_wow['value'];
      dll_wow =join(join(dll_wow[0],dll_wow[1],sep:""), dll_wow[3], sep:".");
    }
    else dll_wow = dll_ver;

    if(dll_ver == dll_wow)
    {
      if(dll_ver == wowver && dll_ver != ver) wownode = TRUE;
      if(!empty_or_null(dll_ver)) bin = TRUE;
    } 
    else
    {
      if(empty_or_null(dll_ver) && !empty_or_null(dll_wow)) wownode = TRUE;
      if(!empty_or_null(dll_ver) || !empty_or_null(dll_wow)) bin = TRUE;
    }
  }
  else if(!empty_or_null(dll_ver)) bin = TRUE;

  if(!bin) audit(AUDIT_UNINST, "McAfee Antivirus");

  return wownode;
} 



#==================================================================#
# Section 2. Main code                                             #
#==================================================================#


get_kb_item_or_exit("SMB/registry_full_access");

services = get_kb_item("SMB/svcs");
#if ( ! services ) exit(0);

login	= kb_smb_login();
pass	= kb_smb_password();
domain  = kb_smb_domain();
port	= kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (empty_or_null(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}


#-------------------------------------------------------------#
# Checks if McAfee VirusScan is installed                     #
#-------------------------------------------------------------#

keys = make_list("SOFTWARE\Network Associates\TVD\Shared Components\VirusScan Engine\4.0.xx",
	 	 "SOFTWARE\McAfee\AVEngine");
item = "DAT";
current_key = NULL;
wow = FALSE;

foreach key(keys)
{
 key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
 current_key  = key;
 if(!empty_or_null(key_h)) break;
}

if ( empty_or_null(key_h) )
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 audit(AUDIT_NOT_INST, "McAfee Antivirus");
}

key_item = RegQueryValue(handle:key_h, item:item);
RegCloseKey(handle:key_h);
if(empty_or_null(key_item))
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 audit(AUDIT_NOT_INST, "McAfee Antivirus");
}

if(current_key == "SOFTWARE\McAfee\AVEngine")
{ 
  wow = check_keys();
}
# Save in the registry. Can be used by another plugin
# Idea from Noam Rathaus
set_kb_item(name: "Antivirus/McAfee/installed", value:TRUE);


#-------------------------------------------------------------#
# Checks the engine version                                   #
#-------------------------------------------------------------#

# Take the first engine version key
engine_version1 = check_engine_version (reg:"SOFTWARE\Network Associates\TVD\Shared Components\VirusScan Engine\4.0.xx", wow:FALSE);
engine_version1 = engine_version1['val'];
# Take the second engine version key
engine_version2 = check_engine_version (reg:"SOFTWARE\Network Associates\TVD\VirusScan Enterprise\CurrentVersion", wow:FALSE);
engine_version2 = engine_version2['val'];
# We keep the more recent version

current_engine_version = NULL;

if ( engine_version1 < engine_version2 )
 current_engine_version = engine_version2;
else
 current_engine_version = engine_version1;

# Check if we can get engine version from a registry key found in v8.5i
# or
# If v85i_engine_version is greater than current_engine_version
# then set current_engine_version to v85i_engine_version (#DKO-22286-986)

v85i_engine_version = NULL;
v85i_engine_version = check_engine_version (reg:"SOFTWARE\McAfee\AVEngine", wow:wow);

if ((!current_engine_version && !empty_or_null(v85i_engine_version)) ||
    (
      (
        !empty_or_null(v85i_engine_version['val']) ||
        !empty_or_null(v85i_engine_version['wow'])
      ) && 
      (
        current_engine_version < v85i_engine_version['val'] ||
        current_engine_version < v85i_engine_version['wow']
      )
    )
   )
 {
  current_engine_version = v85i_engine_version;
 }
#-------------------------------------------------------------#
# Checks the database version                                 #
#-------------------------------------------------------------#

# Initialize var
database_version1 = database_version2 = 0;

# Take the first database version key
database_version1 = check_database_version (reg:"SOFTWARE\Network Associates\TVD\VirusScan Enterprise\CurrentVersion");
database_version1 = database_version1['val'];
# Take the second database version key
database_version2 = check_database_version (reg:"SOFTWARE\Network Associates\TVD\Shared Components\VirusScan Engine\4.0.xx");
database_version2 = database_version2['val'];
# We keep the more recent version
if ( int(database_version1) < int(database_version2) )
{
  current_database_version = database_version2;
  new_database = 0;
}
else
{
  current_database_version = database_version1;
  new_database = 1;
}

# v8.5i ...
v85i_database_version =  check_database_version (reg:"SOFTWARE\McAfee\AVEngine",wow:wow);

if ((!current_database_version && !empty_or_null(v85i_database_version)) ||
    (
      (
      !empty_or_null(v85i_database_version['val']) ||
      !empty_or_null(v85i_database_version['wow'])
      ) && 
      (
      current_database_version < v85i_database_version['val'] || 
      current_database_version < v85i_database_version['wow']
      )
    )
   )
 {
  current_database_version = v85i_database_version;
  if(current_database_version) new_database = 1;
 }


#-------------------------------------------------------------#
# Checks the database date                                    #
#-------------------------------------------------------------#

if (new_database)
  database_date = check_database_date (reg:"SOFTWARE\Network Associates\TVD\VirusScan Enterprise\CurrentVersion");
else
  database_date = check_database_date (reg:"SOFTWARE\Network Associates\TVD\Shared Components\VirusScan Engine\4.0.xx");

database_date = database_date['val'];

# v8.5i ...
if (empty_or_null(database_date))
 {
  database_date = check_database_date (reg:"SOFTWARE\McAfee\AVEngine", wow:wow);
 }

#-------------------------------------------------------------#
# Checks the product version                                  #
#-------------------------------------------------------------#

if (new_database)
{
  product_version = check_item(reg:"SOFTWARE\Network Associates\TVD\VirusScan Enterprise\CurrentVersion", item:"szProductVer");
  product_version = product_version['val'];
}
else
  product_version = NULL;

# v8.5i and later
if (empty_or_null(product_version) || product_version =~ '^8\\.')
{
  product_version = check_item(reg:"SOFTWARE\McAfee\DesktopProtection", item:"szProductVer", wow:wow);
}

#-------------------------------------------------------------#
# Checks the product path                                     #
#-------------------------------------------------------------#

if (new_database)
{
  product_path = check_item(reg:"SOFTWARE\Network Associates\TVD\VirusScan Enterprise\CurrentVersion", item:"szInstallDir");
  product_path = product_path['val'];
}
else
  product_path = NULL;

# v8.5i and later
if (empty_or_null(product_path))
{
  product_path = check_item(reg:"SOFTWARE\McAfee\DesktopProtection", item:"szInstallDir", wow:wow);
}

#-------------------------------------------------------------#
# Checks the product name                                     #
#-------------------------------------------------------------#

if (new_database)
{
  product_name = check_item(reg:"SOFTWARE\Network Associates\TVD\VirusScan Enterprise\CurrentVersion", item:"Product");
  product_name = product_name['val'];
}
else
  product_name = NULL;

# v8.5i ...
if(empty_or_null(product_name))
{
  product_name = check_item(reg:"SOFTWARE\McAfee\DesktopProtection", item:"Product", wow:wow);
}


#-------------------------------------------------------------#
# Checks if ePolicy Orchestror Agent is present               #
#-------------------------------------------------------------#

key = "SOFTWARE\Network Associates\ePolicy Orchestrator\Agent";
item = "Installed Path";

epo_installed = check_item(reg:key, item:item, wow:wow);

#-------------------------------------------------------------#
# Checks if Antivirus is running                              #
#-------------------------------------------------------------#

running = 1;

sc = OpenSCManager (access_mode:SC_MANAGER_CONNECT | SC_MANAGER_QUERY_LOCK_STATUS);
if (!empty_or_null (sc))
{
 service = OpenService (handle:sc, service:"McShield", access_mode:SERVICE_QUERY_STATUS);
 if (!empty_or_null (service))
 {
  status = QueryServiceStatus (handle:service);
  if (!empty_or_null (status))
  {
   if (status[1] != SERVICE_RUNNING)
     running = 0;
  }
  CloseServiceHandle (handle:service);
 }
 CloseServiceHandle (handle:sc);
}


#-------------------------------------------------------------#
# Checks for binary, validity of keys (wow/non wow)           #
#-------------------------------------------------------------#
if(current_key == "SOFTWARE\McAfee\AVEngine")
{
  wow = check_bin(eng_vers:current_engine_version, wow:wow);
  if(wow)
  {
    current_engine_version = current_engine_version["wow"];
    current_database_version = current_database_version["wow"];
    database_date = database_date["wow"];
    product_version = product_version["wow"];
    product_path = product_path["wow"];
    product_name = product_name["wow"];
    epo_installed = epo_installed["wow"];
  }
  else
  {
    current_engine_version = current_engine_version["val"];
    current_database_version = current_database_version["val"];
    database_date = database_date["val"];
    product_version = product_version["val"];
    product_path = product_path["val"];
    product_name = product_name["val"];
    epo_installed = epo_installed["val"];
  }
}

RegCloseKey(handle:hklm);
hotfix_check_fversion_end();

# Save the DAT version in KB for other plugins.
if (!empty_or_null(epo_installed))
  set_kb_item(name: "Antivirus/McAfee/ePO", value:TRUE);

if(current_database_version)
  set_kb_item (name:"Antivirus/McAfee/dat_version", value:current_database_version);

#==================================================================#
# Section 3. Final Report                                          #
#==================================================================#

# var initialization
warning = 0;

#
# We first report information about the antivirus
#
report = "
The remote host has the McAfee antivirus installed.

";

if (product_name)
{
  set_kb_item (name:"Antivirus/McAfee/product_name", value:product_name);
  if (product_version)
  {
    set_kb_item (name:"Antivirus/McAfee/product_version", value:product_version);
    report += "It has been fingerprinted as :
";
    report += product_name + " : " + product_version + "
";
  }
  else
  {
    report += "It has been fingerprinted as :
";
    report += product_name + " : unknown version
";
  }
}

report += "Engine version : " + current_engine_version + "
DAT version : " + current_database_version + "
Updated date : " + database_date + "
";

if (epo_installed)
{
report += "ePO Agent : installed.
";
}
else
{
report += "ePO Agent : not present.
";
}

if (product_path)
{
  set_kb_item (name:"Antivirus/McAfee/product_path", value:product_path);
  report += 'Path : ' + product_path + '\n';
}
else
  report += '\n';


#
# Check if antivirus engine is up to date
#
info = get_av_info("mcafee");
if (empty_or_null(info)) exit(1, "Failed to get McAfee Antivirus info from antivirus.inc.");
last_engine_version = info["last_engine_version"];
datvers = info["datvers"];

# Last Engine Version

if (current_engine_version < int(last_engine_version))
{
  report += "The remote host has an out-dated version of the McAfee
virus engine. Latest version is " + last_engine_version + "

";
  warning = 1;
}

#
# Check if antivirus database is up to date
#

# Last Database Version

if ( int(current_database_version) < int(datvers) )
{
  report += "The remote host has an out-dated version of the McAfee
virus database. Latest version is " + datvers + "

";
  warning = 1;
}

#
# Check if antivirus is running
#

if (services && !running)
{
  report += "The 'McShield' service is not running.

";
  warning = 1;
}

#
# Create the final report
#

if (warning)
{
 report = string ("\n", report);

 security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else
{
  set_kb_item (name:"Antivirus/McAfee/description", value:report);
}
