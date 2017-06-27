#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53490);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/01/12 17:12:45 $");

  script_bugtraq_id(47307);
  script_osvdb_id(71873);
  script_xref(name:"Secunia", value:"44043");

  script_name(english:"IBM Tivoli Monitoring Java Unspecified Vulnerability");
  script_summary(english:"Checks the included version of Java.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Java packaged with IBM Tivoli Monitoring contains a
security vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to the version found in the .properties files, the remote
host has a version of IBM Tivoli Monitoring that contains a Category I
security finding in the packaged version of Java.");

  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg1IZ85351");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 6.2.2 Fix Pack 4 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_monitoring");
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
port    =  kb_smb_transport();

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

# Try to connect to server.

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

# Connect to IPC share.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Failed to connect to IPC share.");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Failed to connect to the remote registry.");
}

# Get the location IBM Tivoli Monitoring was installed at.
path = NULL;
key_h = RegOpenKey(handle:hklm, key:"SOFTWARE\Candle\OMEGAMON", mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"Directory");
  if (! isnull(item))
    path = ereg_replace(string:item[1], pattern:"^(.+)\\$", replace:"\1");

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(1, "Failed to read IBM Tivoli Monitoring's installation path from registry.");
}

# Split the software's location into components.
share = ereg_replace(string:path, pattern:"^([A-Za-z]):.*", replace:"\1$");
dir = ereg_replace(string:path, pattern:"^[A-Za-z]:(.*)", replace:"\1");
file = "\java\java50\jre\bin\launcher.properties";
NetUseDel(close:FALSE);

# Connect to the share software is installed on.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Failed to connect to " + share + " share.");
}

# Get version information for IBM's packaged version of Java.
blob = NULL;
version = NULL;
fh = CreateFile(
  file:dir + file,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (!isnull(fh))
{
  length = GetFileSize(handle:fh);
  blob = ReadFile(handle:fh, offset:0, length:length);
  CloseFile(handle:fh);
}
if (!isnull(blob))
{
  lines = egrep(string:blob, pattern:"^full.version=");
  foreach line (split(lines))
  {
    matches = eregmatch(string:line, pattern:'"J2RE ([0-9.]+) IBM.*"$');
    if (!isnull(matches))
    {
      version = matches;
      version[0] = ereg_replace(string:version[0], pattern:'^"(.+)"$', replace:"\1");

      # Parse SR if possible.
      matches = eregmatch(string:version[0], pattern:"SR([0-9]+)");
      if (!isnull(matches)) sr = int(matches[1]);
      else sr = 0;

      # Parse FP if possible.
      matches = eregmatch(string:version[0], pattern:"FP([0-9]+)");
      if (!isnull(matches)) fp = int(matches[1]);
      else fp = 0;

      version = make_list(version, sr, fp);
      break;
    }
  }
}

# Clean up.
NetUseDel();

# Older versions of IBM Tivoli Monitoring didn't have the java directory, so
# this isn't a failure.
if (isnull(blob))
  exit(0, "Failed to find IBM Tivoli Monitoring's Java installation on the remote host.");

# Check the version of Java.
if (isnull(version))
  exit(1, "Failed to parse " + path + file + " for Java version.");
if (
  (version[1] != "1.5.0") ||
  (version[1] == "1.5.0" && version[2] > 12) ||
  (version[1] == "1.5.0" && version[2] == 12 && version[3] >= 1)
) exit(0, "The host is not affected as it has " + version[0] + ".");

if (report_verbosity > 0)
{
  fix = "J2RE 1.5.0 IBM Windows 32 build pwi32devifx-20110211 (SR12 FP1 +IZ94331)";
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version[0] +
    '\n  Fixed version     : ' + fix + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
