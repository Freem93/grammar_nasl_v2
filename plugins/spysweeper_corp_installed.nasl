#
# (C) Tenable Network Security, Inc.
#

#
# This script has been rewritten by Montgomery County
# Original script was written by Jeff Adams <jeffadams@comcast.net>
# and Tenable Network Security
# This script is released under GPLv2
#
# Tenable grants a special exception for this plugin to use the library
# 'smb_func.inc'. This exception does not apply to any modified version of
# this plugin.
#

include( 'compat.inc' );

if (description)
{
 script_id(21726);
 script_version("$Revision: 1.73 $");
 script_cvs_date("$Date: 2016/12/14 20:33:26 $");

 script_name(english:"Webroot SpySweeper Enterprise Detection");
 script_summary(english:"Checks that SpySweeper is installed and then makes sure the latest Vdefs are loaded.");

  script_set_attribute(attribute:'synopsis', value:"The remote host has an enterprise-class antispyware installed.");

  script_set_attribute(attribute:'description', value:
"This plugin checks that the remote host has Webroot Spy Sweeper
Enterprise installed and properly running, and makes sure that the
latest Vdefs are loaded.");

  script_set_attribute(attribute:'solution', value:
"Make sure Spy Sweeper Enterprise is installed, running, and using the
latest VDEFS.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:'see_also', value:"http://www.webroot.com/business/products/spysweeperenterprise/");


  script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2016 Jeff Adams / Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_full_access.nasl", "smb_enum_services.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access", "SMB/transport", "SMB/Services/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

#

include("smb_func.inc");
include("audit.inc");
include("misc_func.inc");

global_var hklm, login, pass, domain;

#==================================================================#
# Section 1. Utilities                                             #
#==================================================================#

#-------------------------------------------------------------#
# Checks the virus signature version                          #
#-------------------------------------------------------------#
function check_signature_version ()
{
  local_var key, item, key_h, value, path, vers;

  key = "SOFTWARE\Webroot\Enterprise\CommAgent\";
  item = "sdfv";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  value = RegQueryValue(handle:key_h, item:item);

  RegCloseKey (handle:key_h);

  set_kb_item(name: "Antivirus/SpySweeperEnt/signature", value:value[1]);
  return value[1];
}

#-------------------------------------------------------------#
# Checks the product version                                  #
# Ugh -- the only way to determine product version is to look #
# within SpySweeper.exe.                                      #
#-------------------------------------------------------------#
function check_product_version ()
{
  local_var key, item, key_h, value, path, share, exe, conn, fh, version, ver;

  key = "SOFTWARE\Webroot\Enterprise\Spy Sweeper";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h)) {
      value = RegQueryValue(handle:key_h, item:"id");
    if (!isnull(value)) path = value[1];
      else path = NULL;

    RegCloseKey(handle:key_h);
  }
  else path = NULL;

  RegCloseKey(handle:hklm);

  if (isnull(path)) {
    NetUseDel();
    exit(0);
  }
  NetUseDel(close:FALSE);

  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  exe = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\SpySweeperUI.exe", string:path);

  conn = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (conn != 1) {
    NetUseDel();
    exit(0);
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
    exit(0);
  }

  version = GetFileVersion(handle:fh);
  CloseFile(handle:fh);

  if (isnull(version))
  {
    ver = "Unable to determine version";
    set_kb_item(name: "Antivirus/SpySweeperEnt/version", value:ver);
    NetUseDel();
    exit(0);
  }

   ver = string(version[0], ".", version[1], ".", version[2], ".", version[3]);
   set_kb_item(name: "Antivirus/SpySweeperEnt/version", value:ver);

   return ver;
}

#==================================================================#
# Section 2. Main code                                             #
#==================================================================#

services = get_kb_item("SMB/svcs");
#if ( ! services ) exit(0);

get_kb_item_or_exit("SMB/registry_full_access");
get_kb_item_or_exit("SMB/Services/Enumerated");

port = get_kb_item("SMB/transport");
if(!port)port = 139;

name	= kb_smb_name(); 	if(!name)exit(0);
login	= kb_smb_login();
pass	= kb_smb_password();
domain  = kb_smb_domain();
port	= kb_smb_transport();


if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(0);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
 NetUseDel();
 exit(0);
}

#-------------------------------------------------------------#
# Checks if Spy Sweeper Enterprise is installed               #
#-------------------------------------------------------------#

value = NULL;

key = "SOFTWARE\Webroot\Enterprise\Spy Sweeper\";
item = "id";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 value = RegQueryValue(handle:key_h, item:item);
 RegCloseKey (handle:key_h);
}

if ( isnull ( value ) )
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0);
}

set_kb_item(name: "Antivirus/SpySweeperEnt/installed", value:TRUE);


#-------------------------------------------------------------#
# Checks if Spy Sweeper Enterprise has Parent server set      #
#-------------------------------------------------------------#

value = NULL;

key = "SOFTWARE\Webroot\Enterprise\CommAgent\";
item = "su";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 value = RegQueryValue(handle:key_h, item:item);
 RegCloseKey (handle:key_h);
}

if ( strlen (value[1]) <=1 )
{
  set_kb_item(name: "Antivirus/SpySweeperEnt/noparent", value:TRUE);
  RegCloseKey(handle:hklm);
}
else
{
  set_kb_item(name: "Antivirus/SpySweeperEnt/parent", value:value[1]);
}

#-------------------------------------------------------------#
# Checks the virus signature version                          #
#-------------------------------------------------------------#
current_signature_version = check_signature_version ();


#-------------------------------------------------------------#
# Checks if Spy Sweeper is running                            #
# Both of these need to running in order to ensure proper     #
# operation.                                                  #
#-------------------------------------------------------------#

if ( services )
{
  if (("WebrootSpySweeperService" >!< services) || ("Webroot CommAgent Service" >!< services))
    running = 0;
  else
    running = 1;
}


#-------------------------------------------------------------#
# Checks the product version                                  #
#-------------------------------------------------------------#
product_version = check_product_version ();


#-------------------------------------------------------------#
# Section 3. Clean up                                         #
#-------------------------------------------------------------#

RegCloseKey (handle:hklm);
NetUseDel();

#==================================================================#
# Section 4. Final Report                                          #
#==================================================================#

# var initialization
warning = 0;

#
# We first report information about the antivirus
#
report = "
The remote host has the Webroot Spy Sweeper Enterprise installed. It has
been fingerprinted as :

";

report += "Spy Sweeper Enterprise " + product_version + "
DAT version : " + current_signature_version + "

";

#
# Check if antivirus signature is up to date
#

# Last Database Version
# Updates are located here:
# http://www.webroot.com/entcenter/index.php
virus = "868";

if ( int(current_signature_version) < int(virus) )
{
  report += "The remote host has an outdated version of the Spy
Sweeper virus signatures. Last version is " + virus + "

";
  warning = 1;
}


#
# Check if antivirus is running
#

if (services && !running)
{
  report += "The remote Spy Sweeper Enterprise is not running.

";
  set_kb_item(name: "Antivirus/SpySweeperEnt/running", value:FALSE);
  warning = 1;
}
else if (!services)
{
  report += 'Nessus was unable to retrieve a list of running services from the host.\n\n';
  trouble++;
}
else
{
  set_kb_item(name: "Antivirus/SpySweeperEnt/running", value:TRUE);
}

#
# Create the final report
#

if (warning)
{
  report += "As a result, the remote host might be infected by spyware
received by browsing or other means.";

  report = string (
		"\n\nPlugin output :\n\n",
		report);

  security_hole(port:port, extra:report);
}
else
{
  set_kb_item (name:"Antivirus/SpySweeperEnt/description", value:report);
  exit(0, "Detected Webroot SpySweeper Enterprise with no known issues to report.");
}
