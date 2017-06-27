#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50695);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/01/12 17:12:45 $");

  script_cve_id("CVE-2010-4715");
  script_bugtraq_id(44732);
  script_osvdb_id(69138);
  script_xref(name:"Secunia", value:"40820");

  script_name(english:"Novell GroupWise WebAccess Arbitrary File Download (local check) ");
  script_summary(english:"Checks version of GWINTER.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is susceptible to a directory
traversal attack.");
  script_set_attribute(attribute:"description", value:
"The installed version of GroupWise WebAccess fails to perform
sufficient validation on a user specified file name supplied via the
'filename' parameter before returning the contents of the file.

By supplying directory traversal strings such as '../' in a specially
crafted 'GET' request, it may be possible for an attacker to read
arbitrary files from the remote system.");

  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/viewContent.do?externalId=7007156");
  script_set_attribute(attribute:"solution", value:"Apply 8.02 Hot Patch 1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Novell GroupWise 8 WebAccess File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
# Secunia release date.

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/04"); 
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:groupwise_webaccess");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("groupwise_webaccess_accessible.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");
include("audit.inc");

if(report_paranoia < 2)
  get_kb_item_or_exit("www/groupwise-webaccess");

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();
#if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc)  exit(1, "Can't open socket on port "+port+".");

#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}

# Find where it's installed.
path = NULL;
servicename = NULL;

# First get the WebAccess Servicename

key = "SOFTWARE\NOVELL\GroupWise WebAccess\ServiceNames";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[0]; ++i)
  {
    value = RegEnumValue(handle:key_h, index:i);
    # WebAccess (WEBAC80A)
    if (strlen(value[1]) && "WebAccess" >< value[1] )
    {
      servicename = value[1];
      break;
    }
  }
  RegCloseKey(handle:key_h);
}

if(isnull(servicename))
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(1, "It was not possible to determine GroupWise WebAccess servicename.");
}

# Now extract path from EventMessageFile location.

key = "SYSTEM\CurrentControlSet\Services\Eventlog\Application\\"+ servicename;
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"EventMessageFile");
  if (!isnull(value))
  {
    path = value[1];
    # extract the path from EventMessageFile value.
    # for e.g. "c:\Program Files\Novell\GroupWise Server\WebAccess\gwwa1en.dll"
    path = ereg_replace(pattern:'["]*'+"([A-Za-z]:.*)\\[^\\]+" + '["]*', replace:"\1", string:path);
  }
  RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, "GroupWise WebAccess is not installed.");
}

NetUseDel(close:FALSE);

# Grab the file version of GroupWise WebAccess Agent
share = ereg_replace(pattern:'["]*([A-Za-z]):.*', replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\GWINTER.exe", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to "+share+" share.");
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
NetUseDel();

if (isnull(ver))
  exit(1, "Couldn't get the file version of '"+(share-'$')+":"+exe+"'.");

# Check the version number.
version = join(ver, sep:".");
if (ver_compare(ver:version, fix:'8.0.2.11941') == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 8.0.2.11941\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0,"GroupWise WebAccess version "+ version + " is installed and hence is not affected.");
