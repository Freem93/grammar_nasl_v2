#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(54831);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/01/12 17:12:43 $");

  script_bugtraq_id(47947);
  script_osvdb_id(73269, 73270, 73271, 73272, 73273);
  script_xref(name:"EDB-ID", value:"18397");
  script_xref(name:"Secunia", value:"44062");

  script_name(english:"Avaya WinPDM < 3.8.5 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Unite Host Router");

  script_set_attribute(attribute:"synopsis", value:
"A phone administration application on the remote Windows host has
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Avaya WinPDM installed on the remote host has multiple
network services affected by memory corruption vulnerabilities. A
remote, unauthenticated attacker could exploit these issues to execute
arbitrary code.

This plugin determines if the vulnerable software is installed by
checking the file version of the Unite Host Router component of
WinPDM.");
  script_set_attribute(attribute:"see_also", value:"https://support.avaya.com/css/P8/documents/100140122");
  script_set_attribute(attribute:"solution", value:"Upgrade to Avaya WinPDM 3.8.5 (Unite Host Router 4.5.1.5) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-070");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Avaya WinPMD UniteHostRouter Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:avaya:winpdm");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/26");

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
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Connect to the appropriate share.
name    =  kb_smb_name();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();
port    =  kb_smb_transport();
#if (!get_port_state(port)) exit(1, "Port " + port + " is not open.");

# Try to connect to server.
#soc = open_sock_tcp(port);
#if (!soc) exit(1, "Failed to open a socket on port " + port + ".");
#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

# Connect to IPC share.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Failed to connect to IPC$ share.");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Failed to connect to the remote registry.");
}

# Get the installation path from the registry.
# There are vulnerabilities in multiple binaries, but there's
# only one that has a file version in the header, so we'll
# check that one
base = NULL;
key = "SOFTWARE\Ascom Tateco\Unite Host Router";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallationDirectory");
  if (!isnull(item))
    base = item[1];
  RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

if (isnull(base))
{
  NetUseDel();
  exit(0, "No evidence of WinPDM was found in the registry");
}

# Split the software's location into components.
share = ereg_replace(string:base, pattern:"^([A-Za-z]):.*", replace:"\1$");
path = ereg_replace(string:base, pattern:"^[A-Za-z]:(.*)", replace:"\1");
file = "\UniteHostRouter.exe";

# Connect to the share software is installed on.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Failed to connect to " + share + " share.");
}

# Get the version number from the main executable.
version = NULL;
fh = CreateFile(
  file:path + file,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (!isnull(fh))
{
  version = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
else
{
  NetUseDel();
  exit(1, "Failed to open " + base + file + ".");
}

# Clean up.
NetUseDel();

# Ensure that we got a version number.
if (isnull(version))
  exit(1, "Failed to get version of " + base + file + ".");

# Check if the version is vulnerable.
fixed = "4.5.1.5";
version = join(version, sep:".");
if (ver_compare(ver:version, fix:fixed, strict:TRUE) >= 0)
  exit(0, "UHR version " + version + " is not vulnerable.");

# Report our findings.
if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + base + '\\UniteHostRouter.exe' +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
