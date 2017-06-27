#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(48273);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/01/12 17:12:50 $");

  script_cve_id("CVE-2009-3704");
  script_bugtraq_id(42214);
  script_osvdb_id(59047);
  script_xref(name:"EDB-ID", value:"9987");

  script_name(english:"ZoIPer < 2.24 Crafted SIP INVITE Request Remote DoS");
  script_summary(english:"Checks file version of zoiper.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is susceptible to
a denial of service attack.");
  script_set_attribute(attribute:"description", value:
"According to its version, the instance of Zoiper, a VoIP software
phone application, installed on the remote host may crash if it
receives a specially crafted SIP packet.

An unauthenticated, remote attacker can leverage this issue to deny
service to legitimate users.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 2.24 or later as that reportedly addresses the
issue.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The registry wasn't enumerated.");


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

key = "SOFTWARE\Attractel\Zoiper";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, "Zoiper is not installed.");
}
NetUseDel(close:FALSE);


# Check the version of the main exe.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\zoiper.exe", string:path);

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

ver = NULL;
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
NetUseDel();


# Check the version number.
if (!isnull(ver))
{
  version = ver[0] + '.' + ver[2];
  fixed_version = '2.24';

  # nb: we're checking the file version, not the user-friendly version.
  if (ver_compare(ver:ver, fix:"2.0.24.0") == -1)
  {
    if (report_verbosity > 0)
    {
      report =
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fixed_version + '\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
  exit(0, "Zoiper version "+version+" is installed and hence not affected.");
}
else exit(1, "Couldn't get file version of '"+(share-'$')+":"+exe+"'.");
