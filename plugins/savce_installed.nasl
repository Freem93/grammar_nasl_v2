#
# This script has been rewritten by Montgomery County
# Original script was written by Jeff Adams <jeffadams@comcast.net>
# and Tenable Network Security
# This script is released under GPLv2
#

# Changes by Tenable:
# - Revised plugin title (12/19/09)
# - Revised plugin title (06/14/10)
# - Revised plugin title (02/03/16) since multiple products involved
# - Fixed typos (05/06/14)
# - Added check for product edition (08/06/14)
# - Added a check for if we did not get the services (12/04/14)
# - Added a retrieval of HardwareKey (12/02/03)
# - Minor wording changes in the description block (07/01/16)
# - Added detection for Norton Internet Security (07/21/16)
# - Added support for Symantec Endpoint Protection Cloud and Symantec
#   Endpoint Protection Small Business Edition Cloud (12/21/16)
# - Removed forced software path for 64 bit systems. (04/24/17)

include("compat.inc");

if (description)
{
 script_id(21725);
 script_version("$Revision: 1.1708 $");
 script_cvs_date("$Date: 2017/05/02 14:39:08 $");

 script_name(english:"Symantec Antivirus Software Detection and Status");
 script_summary(english:"Checks that Symantec antivirus software is installed and the latest virus definitions are loaded.");

 script_set_attribute(attribute:"synopsis", value:
"An antivirus application is installed on the remote host.");
 script_set_attribute(attribute:"description", value:
"A Symantec antivirus application is installed on the remote host.

Note that this plugin checks that the application is running properly
and that its latest virus definitions are loaded.");
 script_set_attribute(attribute:"solution", value:
"Ensure that updates are working and the associated services are
running.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

 script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/16");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2006-2017 Jeff Adams / Tenable Network Security, Inc.");

 script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_full_access.nasl", "smb_enum_services.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access", "SMB/transport", "SMB/Services/Enumerated");
 script_require_ports(139, 445);

 exit(0);
}

include("audit.inc");
include("antivirus.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

global_var hklm, sep, def_path;

#==================================================================#
# Section 1. Utilities                                             #
#==================================================================#

#-------------------------------------------------------------#
# Checks the virus signature version                          #
#-------------------------------------------------------------#
function check_signature_version ()
{
  local_var key, item, items, key_h, val, value, defkeys, paths, path, vers, sig_full, nav;
  local_var key2, key2_h;
  paths = make_list();
  defkeys = make_array();
  path = NULL;
  vers = NULL;
  nav = FALSE;

  key = "SOFTWARE\Symantec\InstalledApps\";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if ( ! isnull(key_h) )
  {
    # NAV check
    value = RegQueryValue(handle:key_h, item:"NAV");
    if( ! isnull(value) )
    {
      nav = TRUE;
    }

    # definitions check
    value = RegQueryValue(handle:key_h, item:"AVENGEDEFS");
    if ( ! isnull (value) )
    {
      key = "SOFTWARE\Norton\SharedDefs\";
      key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
      if (! isnull(key_h) )
      {
        path = value[1];
        paths = make_list(paths, path);
        defkeys[path] = 'SOFTWARE\\Norton\\SharedDefs\\';
      }
      else
      {
        key = "SOFTWARE\Symantec\SharedDefs\";
        key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
        if ( ! isnull(key_h) )
        {
          path = value[1];
          paths = make_list(paths, path);
          defkeys[path] = 'SOFTWARE\\Symantec\\SharedDefs\\';
        }
      }
    }
  }
  RegCloseKey (handle:key_h);

  if(nav)
  {
    key = 'SOFTWARE\\Norton\\{0C55C096-0F1D-4F28-AAA2-85EF591126E7}\\Common Client\\PathExpansionMap\\';
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if ( ! isnull(key_h) )
    {
       value = RegQueryValue(handle:key_h, item:'APPDATA');
       if ( ! isnull (value) )
       {
         path = value[1];
         paths = make_list(paths, path);
         defkeys[path] = 'SOFTWARE\\Norton\\{0C55C096-0F1D-4F28-AAA2-85EF591126E7}\\SharedDefs\\';

         # Use SharedDefs\SDSDefs if found
         key = defkeys[path] + 'SDSDefs\\';
         key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
         if ( ! isnull(key_h) )
         {
           path = strcat(defkeys[path], 'SDSDefs\\');
           paths = make_list(paths, path);
           defkeys[path] = path;
         }
       }
     RegCloseKey (handle:key_h);
    }
  }
  key = 'SOFTWARE\\Symantec\\Symantec Endpoint Protection\\InstalledApps\\';
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if ( ! isnull(key_h) )
  {
    value = RegQueryValue(handle:key_h, item:'SEPAppDataDir');
    if ( ! isnull(value) )
    {
      path = value[1] + 'Data\\Definitions\\VirusDefs';
      paths = make_list(paths, path);
      defkeys[path] = 'SOFTWARE\\Symantec\\Symantec Endpoint Protection\\CurrentVersion\\SharedDefs';

      path = value[1] + 'Data\\Definitions\\SDSDefs';
      paths = make_list(paths, path);
      defkeys[path] = 'SOFTWARE\\Symantec\\Symantec Endpoint Protection\\CurrentVersion\\SharedDefs\\SDSDefs';
    }
    RegCloseKey (handle:key_h);
  }

  if (max_index(paths) == 0) return NULL;

  foreach path (paths)
  {
    key2 = defkeys[path];
    key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
    if ( ! isnull(key2_h) )
    {
      items = make_list(
        "DEFWATCH_10",
        "NAVCORP_72",
        "NAVCORP_70",
        "NAVNT_50_AP1",
        "AVDEFMGR"
      );

      foreach item (items)
      {
        value = RegQueryValue(handle:key2_h, item:item);
        if (!isnull (value))
        {
          def_path = value[1];
          val = value[1];
          vers = eregmatch(pattern:"\\([0-9]+)(?:\.[0-9]+)?$", string:val);
          if (isnull(vers)) vers = val;
          else vers = vers[1];
        }
      }

      RegCloseKey (handle:key2_h);
    }
  }
  if (isnull(vers)) return NULL;

  sig_full = split(join(def_path), sep:"\");
  sig_full = sig_full[len(sig_full)-1];

  # returning both full and shortened sigs
  set_kb_item(name: "Antivirus/SAVCE/sig_full", value:sig_full);
  set_kb_item(name: "Antivirus/SAVCE/signature", value:vers);

  return vers;
}

#-------------------------------------------------------------#
# Checks AVE version via navex32a.dll                         #
# If DEFWATCH_10 returned a value in check_signature          #
#-------------------------------------------------------------#
function check_ave_version ()
{
  local_var ver, path, fh;


  if(!isnull(def_path))
  {
    path =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\navex32a.dll", string:def_path);

    fh = CreateFile(
      file               : path,
      desired_access     : GENERIC_READ,
      file_attributes    : FILE_ATTRIBUTE_NORMAL,
      share_mode         : FILE_SHARE_READ,
      create_disposition : OPEN_EXISTING
    );
    if (!isnull(fh))
    {
      ver = GetFileVersion(handle:fh);
      ver = join(ver, sep:".");
    }
    if(!isnull(ver)){
      set_kb_item(name: "Antivirus/SAVCE/AVE_version", value:ver);
    }
    CloseFile(handle:fh);
  }

}

#-------------------------------------------------------------#
# Checks the product name                                     #
#-------------------------------------------------------------#

function check_product_name ()
{
  local_var key, item, key_h, value, directory, output, name, vhigh, vlow, v1, v2, v3;

  key = 'SOFTWARE\\Norton\\{0C55C096-0F1D-4F28-AAA2-85EF591126E7}\\';
  item = "PRODUCTNAME";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    name = RegQueryValue(handle:key_h, item:item);
    RegCloseKey(handle:key_h);
    if (!isnull(name))
    {
      set_kb_item(name:'Antivirus/SAVCE/name', value:name[1]);
      return name[1];
    }
  }

 return NULL;
}

#-------------------------------------------------------------#
# Checks the product version                                  #
# Note that major version will only be reported (ie. 9.0.1000 #
#    instead of 9.0.5.1000)                                   #
# Also you can check ProductVersion in                        #
#    HKLM\SOFTWARE\INTEL\LANDesk\VirusProtect6\CurrentVersion #
#-------------------------------------------------------------#

function check_product_version ()
{
  local_var key, item, key_h, value, directory, output, version, vhigh, vlow, v1, v2, v3;

  key = 'SOFTWARE\\Norton\\{0C55C096-0F1D-4F28-AAA2-85EF591126E7}\\';
  item = "PRODUCTVERSION";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    version = RegQueryValue(handle:key_h, item:item);
    RegCloseKey(handle:key_h);
    if (!isnull(version))
    {
      set_kb_item(name:'Antivirus/SAVCE/version', value:version[1]);
      return version[1];
    }
  }

  key = "SOFTWARE\INTEL\LANDesk\VirusProtect6\CurrentVersion";
  item = "ProductVersion";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if ( isnull(key_h) )
  {
   key = 'SOFTWARE\\Symantec\\Symantec Endpoint Protection\\CurrentVersion';
   key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
   if (!isnull(key_h))
   {
     version = RegQueryValue(handle:key_h, item:item);
     RegCloseKey(handle:key_h);
     if (!isnull(version))
     {
       sep = 1;
       set_kb_item(name:'Antivirus/SAVCE/version', value:version[1]);
       return version[1];
     }
   }
   else
   {
     key = "SOFTWARE\Symantec\Symantec Endpoint Protection\SMC";
     key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
     if (!isnull(key_h))
     {
       version = RegQueryValue(handle:key_h, item:item);
       RegCloseKey(handle:key_h);
       if (!isnull(version))
       {
         sep = 1;
         set_kb_item(name:'Antivirus/SAVCE/version', value:version[1]);
         return version[1];
       }
     }
     key = 'SOFTWARE\\Symantec\\Symantec Endpoint Protection\\AV';
     key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
   }
  }

  if ( ! isnull(key_h) )
  {
   version = RegQueryValue(handle:key_h, item:item);

   RegCloseKey (handle:key_h);

   if (!isnull (version))
   {
    vhigh = version[1] & 0xFFFF;
    vlow = (version[1] >>> 16);

    v1 = vhigh / 100;
    v2 = (vhigh%100)/10;
    v3 = (vhigh%10);

    if ( (v1 / 10) > 1 )
    {
      v3 = (v1 / 10 - 1) * 1000;
      v1 = 10 + v1 % 10;
    }

    version = string (v1, ".", v2, ".", v3, ".", vlow);

    set_kb_item(name: "Antivirus/SAVCE/version", value:version);
    return version;
   }
  }

 return NULL;
}

#-------------------------------------------------------------#
# Checks the product type                                     #
#   sepsb = small business edition                            #
#-------------------------------------------------------------#

function check_product_type ()
{
  local_var key, item, key_h, edition;

  item = "ProductType";
  key = "SOFTWARE\Symantec\Symantec Endpoint Protection\SMC\Common";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    edition = RegQueryValue(handle:key_h, item:item);
    RegCloseKey(handle:key_h);
    if (!isnull(edition))
    {
      set_kb_item(name:'Antivirus/SAVCE/edition', value:edition[1]);
      return edition[1];
    }
  }
  return NULL;
}

#-------------------------------------------------------------#
# Checks if a hotfix has been applied to the host             #
#-------------------------------------------------------------#

function check_for_hotfix ()
{
  local_var key, item, key_h, hotfix;

  item = "HOTFIXREVISION";
  key = "SOFTWARE\Symantec\Symantec Endpoint Protection\CurrentVersion";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    hotfix = RegQueryValue(handle:key_h, item:item);
    RegCloseKey(handle:key_h);
    if (!isnull(hotfix))
    {
      set_kb_item(name:'Antivirus/SAVCE/hotfix_applied', value:hotfix[1]);
      return hotfix[1];
    }
  }
  return NULL;
}

#-------------------------------------------------------------#
# Get Hardware Key (if any)                                   #
#   The Hardware Key is a unique identifier used with SEP     #
#   manager                                                   #
#-------------------------------------------------------------#
function get_hardware_key ()
{
  local_var key, item, key_h, hwid;
  key   = "SOFTWARE\Symantec\Symantec Endpoint Protection\SMC\SYLINK\SyLink";
  item  = "HardwareID";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    hwid = RegQueryValue(handle:key_h, item:item);
    RegCloseKey(handle:key_h);

    if (!isnull(hwid))
      return hwid[1];
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

name   = kb_smb_name();
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
# Checks if Symantec AntiVirus Corp is installed              #
#-------------------------------------------------------------#

value  = NULL;
value2 = NULL;

key = "SOFTWARE\Symantec\InstalledApps\";
item = "SAVCE";
item2 = "NAV";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if ( ! isnull(key_h) )
{
 value = RegQueryValue(handle:key_h, item:item);
 value2 = RegQueryValue(handle:key_h, item:item2);
 RegCloseKey (handle:key_h);
}
else
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  audit(AUDIT_NOT_INST, "Symantec Antivirus");
}

if ( isnull ( value ) && isnull (value2) )
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  audit(AUDIT_NOT_INST, "Symantec Antivirus");
}

set_kb_item(name: "Antivirus/SAVCE/installed", value:TRUE);

#-------------------------------------------------------------#
# Checks the virus signature version                          #
#-------------------------------------------------------------#

# Take the first signature version key
current_signature_version = check_signature_version ();

#-------------------------------------------------------------#
# Checks if Antivirus is running                              #
#-------------------------------------------------------------#

# Thanks to Jeff Adams for Symantec service.
if ( services )
{
  if (
    ("Norton AntiVirus" >!< services) &&
    (!egrep(pattern:"\[ *Symantec AntiVirus *\]", string:services, icase:TRUE)) &&
    (get_kb_item('SMB/svc/SepMasterService') != SERVICE_ACTIVE) &&
    # Symantec Endpoint Protection Cloud [ SCS ]
    (get_kb_item('SMB/svc/SCS') != SERVICE_ACTIVE) &&
    # Symantec.cloud Endpoint Protection [ ssSpnA ]
    (get_kb_item('SMB/svc/ssSpnAv') != SERVICE_ACTIVE) &&
    # Norton Internet Security
    ("Norton Internet Security" >!< services) &&
    (get_kb_item('SMB/svc/NIS') != SERVICE_ACTIVE) &&
    ("Norton Security" >!< services) &&
    (get_kb_item('SMB/svc/NS') != SERVICE_ACTIVE)
  )
    running = 0;
  else
    running = 1;
}

#-------------------------------------------------------------#
# Checks the product version                                  #
#-------------------------------------------------------------#
sep = 0;
product_version = check_product_version();

#-------------------------------------------------------------#
# Checks the product name                                     #
#-------------------------------------------------------------#
product_name = check_product_name();

#-------------------------------------------------------------#
# Checks the product type (if applicable) and                 #
# Check if a hotfix has been applied to the host              #
#-------------------------------------------------------------#
if (sep)
{
  product_type = check_product_type();
  hotfix_applied = check_for_hotfix();
}

#-------------------------------------------------------------#
# Checks to see if this instance of SEP is managed and what   #
# the hardware key                                            #
#-------------------------------------------------------------#
hwid = NULL;
if (sep) hwid = get_hardware_key();

if (!isnull(hwid))
{
  replace_kb_item(name:"Host/Identifiers/Symantec Endpoint Protection Manager", value:hwid);
  replace_kb_item(name:"Host/Identifiers", value:TRUE);
  report_xml_tag(tag:'symantec-ep-hardware-key', value:hwid);
}


#-------------------------------------------------------------#
# Checks if Symantec AntiVirus Corp has Parent server set     #
#-------------------------------------------------------------#

key = "SOFTWARE\Intel\LANDesk\VirusProtect6\CurrentVersion\";
item = "Parent";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 parent = RegQueryValue(handle:key_h, item:item);
 RegCloseKey (handle:key_h);
}

if ( strlen (parent[1]) <=1 )
{
  set_kb_item(name: "Antivirus/SAVCE/noparent", value:TRUE);
  RegCloseKey(handle:hklm);
}
else
{
  set_kb_item(name: "Antivirus/SAVCE/parent", value:parent[1]);
}


#-------------------------------------------------------------#
# Close IPC$ share connection, open C$                        #
#-------------------------------------------------------------#
RegCloseKey (handle:hklm);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"C$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "C$");
}

#-------------------------------------------------------------#
# Check AV Engine version                                     #
#-------------------------------------------------------------#
check_ave_version();

#==================================================================#
# Section 3. Clean Up                                              #
#==================================================================#
NetUseDel();

#==================================================================#
# Section 4. Final Report                                          #
#==================================================================#

# var initialization
warning = 0;

#
# We first report information about the antivirus
#
report = "The remote host has antivirus software from Symantec installed. It has
been fingerprinted as :

";

if (sep)
{
  product_name = "Symantec Endpoint Protection";
}

report += product_name + " : " + product_version + "
DAT version : " + current_signature_version + '\n\n';

# Seems this host is managed, report the host guid as well
if (!isnull(hwid))
{
report += 'Hardware key : '+hwid+'\n\n';
}

#
# Check if antivirus signature is up to date
#

# Last Database Version
info = get_av_info("savce");
if (isnull(info)) exit(1, "Failed to get Symantec Antivirus info from antivirus.inc.");
virus = info["virus"];

if ( int(current_signature_version) < ( int(virus) - 1 ) )
{
  report += "The remote host has an outdated version of virus signatures.
Last version is " + virus + "

";
  warning = 1;
}


#
# Check if antivirus is running
#

if (services && !running)
{
  report += 'The remote ' + product_name + ' is not running.\n\n';
  set_kb_item(name: "Antivirus/SAVCE/running", value:FALSE);
  warning = 1;
}
else if (!services)
{
  report += 'Nessus was unable to retrieve a list of running services from the host.\n\n';
  trouble++;
}
else
{
  set_kb_item(name: "Antivirus/SAVCE/running", value:TRUE);
}

#
# Create the final report
#

if (warning)
{
  security_report_v4(
    port:port,
    severity:SECURITY_HOLE,
    extra:
      '\n' +
      report +
      'As a result, the remote host might be infected by viruses received by ' +
      'email or other means.'
  );
}
else
{
  set_kb_item (name:"Antivirus/SAVCE/description", value:report);
  exit(0, "Detected " + product_name + " with no known issues to report.");
}
