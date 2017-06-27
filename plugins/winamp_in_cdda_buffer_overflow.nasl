#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(15817);
 script_version("$Revision: 1.23 $");
 script_cvs_date("$Date: 2015/01/12 17:12:50 $");
 script_cve_id("CVE-2004-1119");
 script_bugtraq_id(11730);
 script_osvdb_id(12093);

 script_name(english:"Winamp < 5.07 IN_CDDA.dll m3u Playlist Processing Overflow");
 script_summary(english:"Determines the version of Winamp");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a multimedia application that is
prone to a buffer overflow attack.");
 script_set_attribute(attribute:"description", value:
"The remote host is using Winamp, a popular media player for Windows.

The version of Winamp installed on the remote Windows host has a
buffer overflow that may allow an attacker to execute arbitrary code
on the remote host subject to the privileges of the user running
Winamp.

To exploit this, an attacker would have to send a malformed playlist
(.m3u) to a user of this host and trick him into loading it with the
application.");
 script_set_attribute(attribute:"solution", value:"Upgrade to Winamp version 5.07 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/11/22");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/23");

script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:nullsoft:winamp");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("netbios_name_get.nasl", "smb_hotfixes.nasl",
 		     "smb_login.nasl","smb_registry_access.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/transport",
                     "SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

#

include("smb_func.inc");
include("audit.inc");
include("smb_hotfixes.inc");

# Connect to the appropriate share.

if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
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
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


# Determine where it's installed.
paths = make_array();

# - various spots in the registry (thanks to Bob Babcock).
keys = make_list(
  "SOFTWARE\Classes\Applications\Winamp.exe\shell\open\command",
  "SOFTWARE\Classes\Directory\shell\Winamp.Play\command",
  "SOFTWARE\Classes\Winamp.File\shell\Play\command",
  "SOFTWARE\Clients\Media\Winamp\shell\open\command"
);
foreach key (keys)
{
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(item))
    {
      path = ereg_replace(pattern:'^"([^"]+)".*$', replace:"\1", string:item[1]);
      path = ereg_replace(pattern:"^(.+)\\winamp\.exe$", replace:"\1", string:path, icase:TRUE);
      paths[path]++;
    }
  }
  RegCloseKey(handle:key_h);

  if (max_index(keys(paths)) > 0 && !thorough_tests) break;
}
RegCloseKey(handle:hklm);
# - default location.
rootfile = hotfix_get_programfilesdir();
if (rootfile && (thorough_tests || max_index(keys(paths)) == 0))
{
  path = rootfile + "\Winamp";
  paths[path]++;
}
if (max_index(keys(paths)) == 0)
{
  NetUseDel();
  exit(0);
}


# Check the version of each product.
info = "";
foreach path (keys(paths))
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\winamp.exe", string:path);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
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
  ver = NULL;
  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);
    CloseFile(handle:fh);
  }

  if (!isnull(ver))
  {
    set_kb_item(name:"SMB/Winamp/Path", value:path);

    version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
    set_kb_item(name:"SMB/Winamp/Version", value:version);

    if (egrep(pattern:"^5\.0\.[0-6]", string:version))
      security_hole(port);
  }
}

NetUseDel();
