#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(47046);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/01/12 17:12:49 $");

  script_cve_id("CVE-2008-4389");
  script_bugtraq_id(40611);
  script_osvdb_id(65601);
  script_xref(name:"CERT", value:"221257");
  script_xref(name:"Secunia", value:"40233");

  script_name(english:"Symantec AppStream / Workspace Streaming Remote Code Execution (SYM10-008)");
  script_summary(english:"Does a local version check");

  script_set_attribute(attribute:"synopsis", value:"The remote host has a code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec AppStream or Symantec Workspace Streaming
running on the remote host has a remote code execution vulnerability.
The client does not properly authenticate to the server before
downloading available files.

A remote attacker could exploit this by setting up a rogue Workspace
Streaming server, forcing clients to download arbitrary files without
the need for user interaction. This could result in arbitrary code
execution.");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2010&suid=20100616_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e6096ebd");
  script_set_attribute(attribute:"solution", value:"Upgrade to Symantec Workspace Streaming 6.1 SP4 (6.2.0.924) or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:workspace_streaming");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:appstream");
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


if (!get_kb_item("SMB/Registry/Enumerated"))
  exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");

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

path = NULL;

# AppStream / SWS use the same registry key
key = "SOFTWARE\AppStream\AppMgr";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  path = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(path)) path = path[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, "No evidence of AppStream/Workspace Streaming was found in the registry.");
}

NetUseDel(close:FALSE);

match = eregmatch(string:path, pattern:'^(([A-Za-z]):(.*\\\\))([^\\\\]+\\.exe)$');
if (!match)
{
  NetUseDel();
  exit(1, "Error parsing exe path '"+path+"'.");
}

dir = match[1];
share = match[2] + '$';
exe = match[3] + match[4];

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

if (!fh)
{
  NetUseDel();
  exit(1, "Error opening '"+path+"'.");
}

ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();

if (isnull(ver)) exit(1, 'Error reading version from '+path);
version = join(ver, sep:'.');

# Check for AppStream 5.2.x and SWS 6.1 < SP4 (6.2.0.924)
if (
  (ver[0] == 5 && ver[1] == 2) ||
  (ver[0] == 6 &&
   (ver[1] < 2 || (ver[1] == 2 && ver[2] == 0 && ver[3] < 924)))
)
{
  NetUseDel();

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : '+dir+
      '\n  Installed version : '+version+
      '\n  Fixed version     : 6.2.0.924\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  exit(0);
}
else exit(0, 'AppStream / SWS version '+version+' is not affected.');
