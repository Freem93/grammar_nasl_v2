#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(30130);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/01/12 17:12:50 $");

  script_cve_id("CVE-2008-0064");
  script_bugtraq_id(27514);
  script_osvdb_id(42832);

  script_name(english:"XnView RGBE File Handling Buffer Overflow");
  script_summary(english:"Checks version of xnview.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that reportedly is
affected by a buffer overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"XnView, an application to view and convert graphic files, is installed
on the remote host.

The version of XnView on the remote host reportedly contains a stack-
based buffer overflow that can be triggered when reading a specially-
crafted Radiance RGBE ('.hdr') file. If an attacker can trick a user
on the affected host into opening such a file, this issue could be
leveraged to execute arbitrary code on the host subject to the user's
privileges.");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2008-1/advisory/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to XnView version 1.92.1 or later as that reportedly resolves
the issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:xnview:xnview");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");


get_kb_item_or_exit("SMB/Registry/Enumerated");


kb_base = "SMB/XnView";


# Figure out where the installer recorded information about it.
key = NULL;

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (!isnull(list))
{
  foreach name (keys(list))
  {
    prod = list[name];
    if (prod && prod =~ "^XnView")
    {
      key = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(.+)\/DisplayName$", replace:"\1", string:name);
      key = str_replace(find:"/", replace:"\", string:key);
      break;
    }
  }
}


# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
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
  exit(1, "Can't connect to the remote registry.");
}


# Find out where it was installed.
path = NULL;

if (!isnull(key))
{
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:"InstallLocation");
    if (!isnull(item))
    {
      path = item[1];
      path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
    }
    RegCloseKey(handle:key_h);
  }
}
if (isnull(path))
{
  key = "SOFTWARE\Classes\Applications\xnview.exe\shell\open\command";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(item))
    {
      path = item[1];
      path = ereg_replace(pattern:'^"(.+)\\\\[^\\\\"]+".*$', replace:"\1", string:path);
    }
    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, "XnView is not installed.");
}


# Determine the version of XnView.exe.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\XnView.exe", string:path);
NetUseDel(close:FALSE);

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
if (isnull(fh))
{
  NetUseDel();
  exit(0, "Failed to open '"+(share-'$')+":"+exe+"'.");
}

set_kb_item(name:kb_base+"/Installed", value:TRUE);
set_kb_item(name:kb_base+"/Path", value:path);

version = GetProductVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();

if (isnull(version)) exit(1, "Couldn't get the file version of '"+(share-'$')+":"+exe+"'.");
set_kb_item(name:kb_base+"/Version", value:version);


# Check the version number.
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 1 ||
  (
    ver[0] == 1 &&
    (
      ver[1] < 92 ||
      (ver[1] == 92 && ver[2] < 1)
    )
  )
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.92.1\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "The XnView " + version + " install is not affected.");
