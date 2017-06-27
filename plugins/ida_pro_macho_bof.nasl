#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51938);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/01/12 17:12:45 $");

  script_cve_id("CVE-2011-1049");
  script_bugtraq_id(46308);
  script_osvdb_id(70846);

  script_name(english:"IDA Pro Mach-O Loader Buffer Overflow");
  script_summary(english:"Checks macho.ldw for patch");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application with a buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IDA Pro, an interactive disassembler, installed on the
remote host is either 5.7 or 6.0 and includes a version of the Mach-O
loader that is affected by a buffer overflow vulnerability.

By tricking a user into opening a specially crafted Mac OS X Mach-O
file using the affected loader, it may be possible for the attacker to
execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"https://www.hex-rays.com/vulnfix.shtml");
  script_set_attribute(attribute:"solution", value:"Apply the vendor's Mach-O loader fix.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");
include("audit.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/IDA Pro_is1/DisplayName");


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
  exit(1, "Can't connect to remote registry.");
}


# Check whether it's installed.
path = NULL;

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\IDA Pro_is1";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"InstallLocation");
  if (!isnull(value))
  {
    path = value[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, "IDA Pro is not installed.");
}


# Check for the affected loader file.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\idag.exe", string:path);
ldw =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\loaders\macho.ldw", string:path);

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
ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);

if (isnull(ver))
{
  NetUseDel();
  exit(1, "Couldn't get file version of '"+(share-'$')+":"+exe+"'.");
}


# Only versions 5.7 and 6.0 are affected.
version = ver[0] + '.' + ver[1];

if (
  (ver[0] == 5 && ver[1] == 7) ||
  (ver[0] == 6 && ver[1] == 0)
)
{
  # Read the affected loader looking for signs it's been patched.
  fh = CreateFile(
    file:ldw,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (isnull(fh))
  {
    NetUseDel();
    exit(0, "Failed to open '"+(share-'$')+":"+ldw+"'.");
  }

  magic1 = 'Bad information in exports, it will be ignored.';
  magic2 = 'FENO SUCH TAG';

  fsize = GetFileSize(handle:fh);
  ofs = 0;
  chunk = 16384;
  patched = FALSE;

  while (fsize > 0 && ofs <= fsize && !patched)
  {
    data = ReadFile(handle:fh, length:chunk, offset:ofs);
    if (strlen(data) == 0) break;
    data = str_replace(find:raw_string(0), replace:"", string:data);

    if (magic1 >< data || magic2 >< data) patched = TRUE;

    # nb: re-read a little bit to make sure we didn't start reading
    #     in the middle of one of our strings.
    ofs += chunk - strlen(magic1);
  }
  CloseFile(handle:fh);
  NetUseDel();

  if (!patched)
  {
    if (report_verbosity > 0)
    {
      report =
        '\n  Path              : ' + path +
        '\n  Loader            : ' + (share-'$') + ":" + ldw +
        '\n  Installed version : ' + version + '\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
else
{
  NetUseDel();
  exit(0, "IDA Pro version "+version+" is installed and not affected.");
}
