#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50603);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/23 20:42:24 $");

  script_bugtraq_id(44502);
  script_osvdb_id(68904);
  script_xref(name:"Secunia", value:"42014");

  script_name(english:"TeamSpeak Client 2.x < 2.0.33.7 Buffer Overflow");
  script_summary(english:"Checks file version of teamspeak.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is susceptible to
buffer overflow.");
  script_set_attribute(attribute:"description", value:
"According to its version, the instance of TeamSpeak 2.x Client, a VoIP
software collaboration application, installed on the remote host is
affected by a buffer overflow vulnerability.

An attacker can corrupt memory on such clients via a specially crafted
voice transmission packet sent via a TeamSpeak server. This corrupted
memory is later used during the teardown process and can lead to
execution of arbitrary code.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 2.0.33.7 or later as that reportedly addresses the
issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"see_also", value:"http://www.nsense.fi/advisories/nsense_2010_002.txt");
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.cert.fi/en/reports/2010/vulnerability404670.html"
  );

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

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

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/Teamspeak*");
if (isnull(list)) exit(0, "No registry items related to a TeamSpeak installation were found.");

key = NULL;
foreach name (keys(list))
{
  prod = list[name];
  if (prod && prod =~ "^TeamSpeak")
  {
    key = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(.+)\/DisplayName$", replace:"\1", string:name);
    key = str_replace(find:"/", replace:"\", string:key);
    break;
  }
}
if (isnull(key)) exit(1, "Unable to find KB item for TeamSpeak uninstall registry key");

# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');


# Connect to remote registry.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}


# Find where it's installed.
path = NULL;
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"UninstallString");
  if (!isnull(value))
  {
    path = value[1];
    path = ereg_replace(pattern:"^(.+)\\[^\\\\]+$", replace:"\1", string:path);
  }

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, "TeamSpeak Client is not installed.");
}
NetUseDel(close:FALSE);


# Check the version of the main exe.
path = str_replace(string:path, find:'"', replace:'');
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\TeamSpeak.exe", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to "+share+" share.");
}

fh = CreateFile(
  file               : exe,
  desired_access     : GENERIC_READ,
  file_attributes    : FILE_ATTRIBUTE_NORMAL,
  share_mode         : FILE_SHARE_READ,
  create_disposition : OPEN_EXISTING
);
if (isnull(fh))
{
  NetUseDel();
  exit(0, "Failed to open '"+(share-'$')+":"+exe+"'.");
}

ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();


# Check the version number.
if (!isnull(ver))
{
  version = join(ver, sep:".");
  fixed_version = '2.0.33.7';

  if (ver_compare(ver:ver, fix:fixed_version) == -1)
  {
    if (report_verbosity > 0)
    {
      report =
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fixed_version + '\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
  exit(0, "Teamspeak Client version "+version+" is installed and hence not affected.");
}
else exit(1, "Couldn't get file version of '"+(share-'$')+":"+exe+"'.");
