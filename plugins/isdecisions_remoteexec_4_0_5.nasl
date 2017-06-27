#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45087);
  script_version("$Revision: 1.6 $");
 script_cvs_date("$Date: 2015/01/12 17:12:45 $");

  script_bugtraq_id(38763);
  script_osvdb_id(62998);
  script_xref(name:"Secunia", value:"38733");

  script_name(english:"IS Decisions RemoteExec '.rec' Remote Buffer Overflow");
  script_summary(english:"Checks the version of RemoteExec");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a computer-management application that is
affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running IS Decisions RemoteExec, a computer-
management application.

The installed version is earlier than 4.0.5. Such versions are
potentially affected by a buffer overflow vulnerability when
processing specially crafted '.rec' files.

An attacker, exploiting this flaw, could potentially execute arbitrary
code subject to the privileges of the user running the affected
application.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ab1d3b77");
  script_set_attribute(attribute:"see_also", value:"http://www.isdecisions.com/en/software/remoteexec/history.cfm");
  script_set_attribute(attribute:"solution", value:"Upgrade to IS Decisions RemoteExec 4.0.5 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/18");

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

include("misc_func.inc");
include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");

# Connect to the appropriate share.
name   = kb_smb_name();
port   = kb_smb_transport();

login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();


if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass,domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Could not connect to the IPC$ share.");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Could not connect to the remote registry.");
}

# Determine the install location.
path = NULL;

reg = "SOFTWARE\ISDecisions\RemoteExec";
key_h = RegOpenKey(handle:hklm, key:reg, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"LogFolder");
  if (!isnull(item)) path = item[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, "IS Decisions RemoteExec does not appear to be installed.");
}
NetUseDel(close:FALSE);
path = ereg_replace(pattern:"^([A-Za-z]:.*)\\Logs", replace:"\1", string:path);

# Determine the version from the executable.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\RemoteExec.exe", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to '"+share+"' share.");
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
  exit(1, "Unable to access IS Decisions RemoteExec executable (" +exe + ").");
}

version = GetProductVersion(handle:fh);
version = str_replace(find:", ", replace:".", string:version);
CloseFile(handle:fh);
NetUseDel();

if (isnull(version)) exit(1, "Failed to get file version of '"+exe+"'.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 4 ||
  (ver[0] == 4 && ver[1] == 0 && ver[2] < 5)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      'Product            : IS Decisions RemoteExec\n' +
      'Path               : ' + path + '\n' +
      'Installed version  : ' + version + '\n' +
      'Fixed version      : 4.0.5\n';

    security_hole(port:port, extra:report);
  }
  else security_hole(port:port);
  exit(0);
}
else exit(0, "IS Decisions RemoteExec version "+version+" is installed and thus not affected.");
