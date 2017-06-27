#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33902);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2008-3676");
  script_bugtraq_id(30663);
  script_xref(name:"OSVDB", value:"47459");

  script_name(english:"hMailServer < 4.4.2 build 279 IMAP Command Handling Remote DoS");
  script_summary(english:"Checks hMailServer version"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a denial of
service vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running hMailServer, a mail server for Windows. 

By sending large amounts of data along with certain IMAP commands such
as 'CREATE' or 'RENAME', an authenticated user may be able to crash
the remote mail server." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/495361" );
 script_set_attribute(attribute:"see_also", value:"http://www.hmailserver.com/documentation/?page=changelog" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to hMailServer 4.4.2-B279 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/08/16");
 script_cvs_date("$Date: 2016/05/11 13:32:17 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "find_service1.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports("Services/imap", 139, 445);

  exit(0);
}

include("global_settings.inc");
include("imap_func.inc");
include("smb_func.inc");

# Make sure hMailServer's IMAP service is running.
if (report_paranoia < 2)
{
 port = get_kb_item("Services/imap");
 if (!port) port = 143;
 if (!get_port_state(port)) exit(0);

 banner = get_imap_banner(port:port);
 if (banner && banner != '* OK IMAPrev1\r\n') exit(0);
}

# Figure out where the installer recorded information about it.
# We will rely on this version later, if required.

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (isnull(list)) exit(0);

installstring = NULL;
hmail_version = NULL;

foreach name (keys(list))
{
  prod = list[name];
  if (prod && "hMailServer" >< prod)
  {
    installstring = ereg_replace(pattern:"^(SMB\/Registry\/HKLM\/SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
    hmail_version = prod;
    break;
  }
}

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

key = "SOFTWARE\hMailServer";
path = NULL;

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  # If hMailServer is installed..
  item = RegQueryValue(handle:key_h, item:"InstallLocation");
  if (!isnull(item)) path = item[1];
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (!path)
{
 NetUseDel();
 exit(0);
}


share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Bin\hMailAdmin.exe", string:path);
NetUseDel(close:FALSE);

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
  ret = GetFileVersionEx(handle:fh);
  if (!isnull(ret)) children = ret['Children'];

  stringfileinfo = children['StringFileInfo'];
  if (!isnull(stringfileinfo))
  {
    foreach key (keys(stringfileinfo))
    {
      data = stringfileinfo[key];
      if (!isnull(data))
      {
        ver = data['Comments'];
        break;
      }
    }
  }	
  CloseFile(handle:fh);
}

# nb: We do a sanity check to ensure hMailServer.exe exists, 
#     if we could not get version off FileVersion Comments.
	 
if(isnull(ver))
{
 exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Bin\hMailServer.exe", string:path);
 
 fh = CreateFile(file:exe,
        desired_access:GENERIC_READ,
        file_attributes:FILE_ATTRIBUTE_NORMAL,
        share_mode:FILE_SHARE_READ,
        create_disposition:OPEN_EXISTING);

  if (!isnull(fh))
  {
   ver = GetFileVersion(handle:fh);
   CloseFile(handle:fh);
  }
} 

NetUseDel();

  
if(!ver) exit(0);

# nb : We rely on the version obtained from FileVersion Comments.
#      However, if the version is not correct we 
#      rely on installer entries for version info.

if(ver && ereg(pattern:"^[0-9]+\.[0-9]+\.*[0-9]*-[A-Z][0-9]+$",string:ver)) hmail_version = ver;

# If we come here hmail_version was probably not set by the 
# file version.
if("hMailServer" >< hmail_version)
hmail_version = strstr(hmail_version,"hMailServer ") - "hMailServer "; # hMailServer 4.4.2-B279

# If we get the version ...
if (hmail_version)
{
  build 	= ereg_replace(pattern:"^ *[0-9]\.[0-9]\.*[0-9]* *\-[A-Z]([0-9]+)",string:hmail_version,replace:"\1");
  version       = ereg_replace(pattern:"^ *([0-9]\.[0-9]\.*[0-9]*) *\-[A-Z][0-9]+",string:hmail_version,replace:"\1");

  # Check the version number.
  if ( (ereg(pattern:"^([0-3]\.|4\.([0-3]\.|4($|\.[0-1]|-)))",string:version)) ||  # Flag < 4.4.1
       (ereg(pattern:"^4.4.2-B",string:version) && (int(build) < 279 ))	 	   # Flag < 4.4.2-B279
     )	
   {
      if (report_verbosity)
       {
         report = string(
          "\n",
          "hMailServer version ", hmail_version, " is installed on the remote host.\n"
         );
         security_warning(port:port, extra:report);
       }
       else
         security_warning(port);
   }
} 
