#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2011/07/27  


include("compat.inc");

if(description)
{
 script_id(24344);
 script_version("$Revision: 1.766 $");

 script_name(english:"Windows Live OneCare Antivirus Detection");

 script_set_attribute(attribute:"synopsis", value:
"An antivirus is installed on the remote host, but it is not working
properly." );
 script_set_attribute(attribute:"description", value:
"Windows Live OneCare antivirus, a commercial antivirus software
package for Windows, is installed on the remote host; however, there
is a problem with the install in that either its services are not
running, or its engine and/or virus definition are out of date." );
 script_set_attribute(attribute:"solution", value:
"Make sure updates are working and the associated services are
running." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/14");
 script_cvs_date("$Date: 2014/05/06 21:56:49 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:windows_live_onecare");
script_end_attributes();

 script_summary(english:"Checks that the remote host has Windows Live OneCare antivirus installed and then makes sure the latest Vdefs are loaded."); 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_full_access.nasl", "smb_enum_services.nasl"); 
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access","SMB/transport");
 script_require_ports(139, 445); 
 exit(0);
}

include("smb_func.inc");


global_var hklm;

#==================================================================#
# Section 1. Utilities                                             #
#==================================================================#


function _check_version (v1, v2)
{
 v1 = split(v1,sep:".",keep:FALSE);
 v2 = split(v2,sep:".",keep:FALSE);

 if ( ( int(v1[0]) < int(v2[0]) ) ||
      ( int(v1[0]) == int(v2[0]) && int(v1[1]) < int(v2[1]) ) ||
      ( int(v1[0]) == int(v2[0]) && int(v1[1]) == int(v2[1]) && int(v1[2]) < int(v2[2]) ) ||
      ( int(v1[0]) == int(v2[0]) && int(v1[1]) == int(v2[1]) && int(v1[2]) == int(v2[2]) && int(v1[3]) < int(v2[3]) ) )
  return TRUE;

 return FALSE;
}


#-------------------------------------------------------------#
# Checks the engine version                                   #
#-------------------------------------------------------------#
function check_engine_version ()
{
  local_var key, item, key_h, value, vers;

  key = "SOFTWARE\Microsoft\OneCare Protection\Signature Updates"; 
  item = "EngineVersion";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if ( ! isnull(key_h) )
  {
   value = RegQueryValue(handle:key_h, item:item);
   RegCloseKey (handle:key_h);

   if (!isnull (value))
   {
    vers = value[1];
    set_kb_item(name:"Antivirus/OneCare/onecare_engine_version", value:vers);
    return vers;
   }
  }
  
  return NULL;
}


#-------------------------------------------------------------#
# Checks the anti spyware version                             #
#-------------------------------------------------------------#
function check_as_version ()
{
  local_var key, item, key_h, value;

  key = "SOFTWARE\Microsoft\OneCare Protection\Signature Updates"; 
  item = "ASSignatureVersion";
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


#-------------------------------------------------------------#
# Checks the antivirus version                                #
#-------------------------------------------------------------#
function check_av_version ()
{
  local_var key, item, key_h, value;

  key = "SOFTWARE\Microsoft\OneCare Protection\Signature Updates"; 
  item = "AVSignatureVersion";
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


services = get_kb_item("SMB/svcs");
#if ( ! services ) exit(0);

access = get_kb_item("SMB/registry_full_access");
if ( ! access ) exit(0);


name	= kb_smb_name();
login	= kb_smb_login(); 
pass	= kb_smb_password(); 	
domain  = kb_smb_domain(); 	
port	= kb_smb_transport();

if ( ! get_port_state(port) ) exit(0);
soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(0);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) ) 
{
 NetUseDel();
 exit(0);
}


#-------------------------------------------------------------#
# Checks if Windows Live OneCare is installed                 #
#-------------------------------------------------------------#


key = "SOFTWARE\Microsoft\OneCare Protection";
item = "InstallLocation";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 value = RegQueryValue(handle:key_h, item:item);

 if (isnull (value))
 {
  RegCloseKey (handle:hklm);
  NetUseDel ();
  exit(0);
 }

 RegCloseKey (handle:key_h);
}
else exit(0);

# Save in the registry. Can be used by another plugin
set_kb_item(name: "Antivirus/OneCare/installed", value:TRUE);


#-------------------------------------------------------------#
# Checks the engine version                                   #
#-------------------------------------------------------------#

current_engine_version = check_engine_version (); 


#-------------------------------------------------------------#
# Checks the anti spyware version                             #
#-------------------------------------------------------------#

current_as_version = check_as_version (); 


#-------------------------------------------------------------#
# Checks the anti spyware version                             #
#-------------------------------------------------------------#

current_av_version = check_av_version (); 


#-------------------------------------------------------------#
# Checks if Antivirus is running                              #
#-------------------------------------------------------------#

##### Is the OneCareMP service running ? ######

if ( services )
{
  if ("OneCareMP" >< services)
    running = 1;
  else 
    running = 0;
}


RegCloseKey (handle:hklm);
NetUseDel ();


#==================================================================#
# Section 3. Final Report                                          #
#==================================================================#

# var initialization
warning = 0;

#
# We first report information about the antivirus
#
report = "
The remote host has Windows Live OneCare installed.
It has been fingerprinted as :

Engine version : " + current_engine_version + "
Spyware Def version : " + current_as_version + "
Virus Def version : " + current_av_version + "

";


#
# Check if antivirus engine is up to date
#

# Last Engine Version
last_engine_version="1.1.6802.0";

if (_check_version(v1:current_engine_version, v2:last_engine_version))
{
  report += "The remote host has an out-dated version of the Live OneCare
engine. Last version is " + last_engine_version + "

";
  warning = 1;
}



#
# Check if antivirus database is up to date
#

# Last Database Date
avvers="1.103.1557.0";

if (_check_version(v1:current_av_version, v2:avvers))
{
  report += "The remote host has an out-dated version of the Live OneCare
virus database. Last version is " + avvers + "

";
  warning = 1;
}



#
# Check if spyware database is up to date
#

# Last Database Date
asvers="1.103.1557.0";

if (_check_version(v1:current_as_version, v2:asvers))
{
  report += "The remote host has an out-dated version of the Live OneCare
spyware database. Last version is " + asvers + "

";
  warning = 1;
}




#
# Check if antivirus is running
#

if (services && !running)
{
  report += "The remote Windows Live OneCare antivirus & antispyware are not running.

";
  warning = 1;
}




#
# Create the final report
#

if (warning)
{
  report += "As a result, the remote host might be infected by viruses received by
email or other means.";

  report = string ("\n", report);

  security_hole(port:port, extra:report);
}
else
{
  set_kb_item (name:"Antivirus/OneCare/description", value:report);
}

