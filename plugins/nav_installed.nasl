#
# This script has been rewritten by Tenable Network Security
# Original script was written by Jeff Adams <jeffadams@comcast.net>;
#
# @DEPRECATED@
#
# Disabled on 2017/04/24. Deprecated by savce_installed.nasl
#
# This script is released under GPLv2
#
# Tenable grants a special exception for this plugin to use the library
# 'smb_func.inc'. This exception does not apply to any modified version of
# this plugin.
#

include("compat.inc");

if (description)
{
 script_id(12106);
 script_version("$Revision: 1.1879 $");
 script_cvs_date("$Date: 2017/05/02 14:39:08 $");

 script_name(english:"Norton AntiVirus Detection and Status (deprecated)");
 script_summary(english:"Checks that Norton AntiVirus is installed and then makes sure the latest Vdefs are loaded.");

 script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
 script_set_attribute(attribute:"description", value:
"This plugin has been deprecated. It has been replaced by Symantec
Antivirus Software Detection and Status, ID 21725.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/03/16");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2004-2017 Jeff Adams / Tenable Network Security, Inc.");

 script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_full_access.nasl", "smb_enum_services.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access", "SMB/transport", "SMB/Services/Enumerated");
 script_require_ports(139, 445);

 exit(0);
}

exit(0, "This plugin has been deprecated. Use savce_installed.nasl (plugin ID 21725) instead.");

include("audit.inc");
include("antivirus.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

global_var hklm, key_360;

key_360 = NULL;

#==================================================================#
# Section 1. Utilities                                             #
#==================================================================#

#-------------------------------------------------------------#
# Checks the engine version                                   #
#-------------------------------------------------------------#
function check_database_version ()
{
  local_var key, item, key_h, key_h1, subkey, value, path, vers, info, i;

  vers = NULL;

  key = "SOFTWARE\Symantec\SharedDefs\";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"DEFWATCH_10");
    if (isnull (value))
      value = RegQueryValue(handle:key_h, item:"NAVCORP_70");
    if (isnull (value))
      value = RegQueryValue(handle:key_h, item:"NAVNT_50_AP1");
    if (isnull (value))
      value = RegQueryValue(handle:key_h, item:"AVDEFMGR");

    RegCloseKey (handle:key_h);

    if (!isnull (value))
      vers = value[1];
  }

  if(!isnull(vers))
  {
    key = "SOFTWARE\Symantec\InstalledApps\";
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      value = RegQueryValue(handle:key_h, item:"AVENGEDEFS");

      RegCloseKey (handle:key_h);

      if(!isnull (value))
      {
        path = value[1];
        vers = substr (vers, strlen(path) + 1 , strlen(vers)-5);
        return vers;
      }
    }
  }

  key = "SOFTWARE\Norton";
  if (get_kb_item("SMB/WoW"))
    key = ereg_replace(pattern:"^SOFTWARE\\(.*)", string:key, replace:"SOFTWARE\\Wow6432Node\\\1", icase:TRUE);

  # find Norton 360 Installs
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    info = RegQueryInfoKey(handle:key_h);
    if (isnull(info))
    {
      RegCloseKey (handle:key_h);
      return NULL;
    }
    for (i = 0; i < info[1]; i++)
    {
      subkey = RegEnumKey(handle:key_h, index:i);
      if (isnull(subkey))
      {
        RegCloseKey (handle:key_h);
        return NULL;
      }

      key_h1 = RegOpenKey(handle:hklm, key:key+"\"+subkey, mode:MAXIMUM_ALLOWED);
      value = RegQueryValue(handle:key_h1, item:"PRODUCTNAME");
      RegCloseKey(handle:key_h1);

      if(value[1] !~ "^Norton 360")
        continue;

      key_h1 = RegOpenKey(handle:hklm, key:key+"\"+subkey+"\SharedDefs", mode:MAXIMUM_ALLOWED);

      value = RegQueryValue(handle:key_h1, item:"AVDEFMGR");
      RegCloseKey(handle:key_h1);

      if(isnull(value))
      {
        value = RegQueryValue(handle:key_h1, item:"SRTSP");
        RegCloseKey(handle:key_h1);
      }

      if(!isnull(value))
      {
        path = value[1];
        item = eregmatch(pattern:"\\([0-9]+)(\.[0-9]+)?$", string:path);
        if(!isnull(item[1]))
        {
          RegCloseKey (handle:key_h);
          key_360 = key+"\"+subkey;
          return item[1];
        }
      }
    }
  }
  RegCloseKey (handle:key_h);
  return NULL;
}

#-------------------------------------------------------------#
# Checks the product version                                  #
#-------------------------------------------------------------#
function check_product_version (reg, val)
{
  local_var key, item, key_h, value;

  key = reg;
  if(isnull(val))
    item = "version";
  else item = val;
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if ( ! isnull(key_h) )
  {
   value = RegQueryValue(handle:key_h, item:item);
   RegCloseKey (handle:key_h);

   if (!isnull (value))
     return value[1];
  }

  return NULL;
}

#==================================================================#
# Section 2. Main code                                             #
#==================================================================#

get_kb_item_or_exit("SMB/registry_full_access");
get_kb_item_or_exit("SMB/Services/Enumerated");

services = get_kb_item("SMB/svcs");
#if ( ! services ) exit(0);

login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();
port   = kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}


#-------------------------------------------------------------#
# Checks if Norton AV is installed                            #
#-------------------------------------------------------------#

value = NULL;
value1 = NULL;
value2 = NULL;

installed = FALSE;

key = "SOFTWARE\Symantec\InstalledApps\";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
  value = RegQueryValue(handle:key_h, item:"NAVNT");
  value1 = RegQueryValue(handle:key_h, item:"SAVCE");
  value2 = RegQueryValue(handle:key_h, item:"Norton 360");
  if((!isnull(value) && isnull(value1)) ||
     !isnull(value2))
    installed = TRUE;
 RegCloseKey (handle:key_h);
}

if (!installed)
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0);
}

set_kb_item(name: "Antivirus/Norton/installed", value:TRUE);

#-------------------------------------------------------------#
# Checks the virus database version                           #
#-------------------------------------------------------------#

# Take the first database version key
current_database_version = check_database_version ();

#-------------------------------------------------------------#
# Checks if Antivirus is running                              #
#-------------------------------------------------------------#
# Thanks to Jeff Adams for Symantec service.
if ( services )
{
  if (("Norton AntiVirus" >!< services) && ("Symantec AntiVirus" >!< services) &&
      ("SymAppCore" >!< services) && ("Norton 360" >!< services))
    running = 0;
  else
    running = 1;
}

#-------------------------------------------------------------#
# Checks the product version                                  #
#-------------------------------------------------------------#

product_version = check_product_version (reg:"SOFTWARE\Symantec\Norton AntiVirus");
if(isnull(product_version) && !isnull(key_360))
  product_version = check_product_version (reg:key_360, val: "PRODUCTVERSION");

RegCloseKey (handle:hklm);
NetUseDel();

#==================================================================#
# Section 3. Final Report                                          #
#==================================================================#

# var initialization
warning = 0;

#
# We first report information about the antivirus
#
report = "
The remote host has Norton AntiVirus installed. It has been
fingerprinted as :

";

report += "Norton/Symantec Antivirus " + product_version + "
DAT version : " + current_database_version + "

";

#
# Check if antivirus database is up-to-date
#

# Last Database Version
info = get_av_info("nav");
if (isnull(info)) exit(1, "Failed to get Norton AntiVirus info from antivirus.inc.");
virus = info["virus"];

if ( int(current_database_version) < ( int(virus) - 1 ) )
{
  report += "The remote host has an outdated version of the Norton
virus database. Last version is " + virus + "

";
  warning = 1;
}


#
# Check if antivirus is running
#
if (services && !running)
{
  report += "The remote Norton AntiVirus is not running.

";
  warning = 1;
}
else if (!services)
{
  report += 'Nessus was unable to retrieve a list of running services from the host.\n\n';
  trouble++;
}

#
# Create the final report
#

if (warning)
{
  report += "As a result, the remote host might be infected by viruses received by
email or other means.";

  report = string (
                "\n",
		report);

  security_hole(port:port, extra:report);
}
else
{
  set_kb_item (name:"Antivirus/Norton/description", value:report);
  exit(0, "Detected Norton Antivirus with no known issues to report.");
}

