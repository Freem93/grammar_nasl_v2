#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(34060);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2008-7104", "CVE-2008-7105");
  script_bugtraq_id(30881);
  script_osvdb_id(57493, 57499);

  script_name(english:"Sophos PureMessage < 3.0.2 Multiple Vulnerabilities");
  script_summary(english:"Checks Sophos PureMessage version"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Sophos PureMessage for Microsoft Exchange. 
The installed version of the software is affected by multiple
vulnerabilities. 

  - A vulnerability in PMScanner.exe could crash or hang the
    PureMessage Scanner service while processing certain 
    rich text (RTF) or PDF files.

  - A vulnerability in PureMessage could abruptly terminate 
    EdgeTransport.exe while replacing rich text body of 
    certain TNEF-encoded messages with plaintext." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Sophos PureMessage 3.0.2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/08/28");
 script_set_attribute(attribute:"patch_publication_date", value: "2008/08/28");
 script_cvs_date("$Date: 2015/06/23 19:16:51 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl","find_service1.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");

# Check if imap/pop3 services are listening.

if (report_paranoia < 2)
{
  list = get_kb_list("Services/imap");
  if ( isnull(list) ) port = 143;
  else port = list[0];

  if (!get_port_state(port))
  {
   list = get_kb_list("Services/pop3");
   if ( isnull(list) ) port = 110;
   else port = list[0];
   if ( ! get_port_state(port) ) exit(0);
  }
} 

# Figure out where the installer recorded information about it.

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (isnull(list)) exit(0);

installstring = NULL;

foreach name (keys(list))
{
  prod = list[name];
  if (prod && "Sophos PureMessage" >< prod)
  {
    installstring = ereg_replace(pattern:"^(SMB\/Registry\/HKLM\/SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
    break;
  }
}

if (isnull(installstring)) exit(0);

pm_version = get_kb_item(string(installstring,"/","DisplayVersion"));

# Get the install path

name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if (!get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}

key = "SOFTWARE\Sophos\MMEx";
path = NULL;

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  # If PureMessage is installed..
  item = RegQueryValue(handle:key_h, item:"InstallPath");
  if (!isnull(item)) path = item[1];
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (!path)
{
 NetUseDel();
 exit(0);
}

NetUseDel(close:FALSE);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Bin\PMScanner.exe", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
 NetUseDel();
 exit(0);
}

fh = CreateFile(file:exe, 
	desired_access:GENERIC_READ, 
	file_attributes:FILE_ATTRIBUTE_NORMAL, 
	share_mode:FILE_SHARE_READ, 
	create_disposition:OPEN_EXISTING);

ver = NULL;
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}

NetUseDel();
  
# nb :
# We don't rely on FileVersion, since the version
# in the registry is accurate.

if (ver)
{
 # Version that is not vulnerable.
  fix = split("3.0.2",    sep:'.', keep:FALSE);
  ver = split(pm_version, sep:'.', keep:FALSE);
 	
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity)
      { 
        report = string(
          "\n",
          "Version ", pm_version, " of Sophos PureMessage is installed on the\n",
          " remote host under :\n\n",
	  "	",path,
	  "\n"
        );
        security_warning(port:port, extra:report);
      }
      else security_warning(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
} 
