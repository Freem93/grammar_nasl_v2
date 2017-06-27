#
# (C) Tenable Network Security, Inc.
#

include ("compat.inc");

if (description)
{
  script_id(44939);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/01/15 16:37:15 $");

  script_cve_id("CVE-2010-0189");
  script_bugtraq_id(38313);
  script_osvdb_id(62547);

  script_name (english:"Adobe Download Manager Arbitrary File Download (APSB10-08)");
  script_summary (english:"Checks the version of getPlusPlus_Adobe.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a download manager installed that is prone
to an arbitrary file download vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of Adobe Download Manager
earlier than 1.6.2.63 installed. Such versions are potentially
affected by a vulnerability that allows an attacker to download and
install unauthorized software onto a user's system.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb10-08.html");
  script_set_attribute(attribute:"see_also", value:"http://blogs.adobe.com/psirt/2010/02/security_update_released_for_t.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/509720/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Either upgrade to Adobe Download Manager version 1.6.2.63 or uninstall
the application.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:download_manager");
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

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (isnull(list)) exit(1, "The 'SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall' KB items are missing.");

installstring = NULL;
foreach name (keys(list))
{
  prod = list[name];
  if (prod && 'Adobe Download Manager' >< prod)
  {
    installstring = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
    installstring = str_replace(find:"/", replace:"\", string:installstring);
  }
}
if (isnull(installstring)) exit(0, "No evidence of Adobe Download Manager was found in the registry.");

#Connect to the appropriate share
name     = kb_smb_name();
port     = kb_smb_transport();
#if (!get_port_state(port)) exit(0);
login    = kb_smb_login();
pass     = kb_smb_password();
domain   = kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc)
#  exit(1, "Could not open socket to port "+port+".");

#session_init(socket:soc, hostname:name);

if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to the remote registry.");
}

# Determine where it's installed.
path = NULL;
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
key_h = RegOpenKey(handle:hklm, key:installstring, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallLocation");
  if (!isnull(item)) path = item[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(1, "The Adobe Download Manager install location could not be found in the registry.");
}
NetUseDel(close:FALSE);


# Determine the version from the executable.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\getPlusPlus_Adobe.exe", string:path);

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

# Grab the version number if the file was opened successfully.
if (isnull(fh))
{
  NetUseDel();
  exit(0, "Unable to access Adobe Download Manager executable : " + exe);
}

version = GetProductVersion(handle:fh);
CloseFile(handle:fh);
if (isnull(version)) exit(1, "Failed to get file version of '"+exe+"'.");

version = ereg_replace(string:version, pattern:',', replace:'.');

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] < 1 ||
  (
    ver[0] == 1 &&
    (
      ver[1] < 6 ||
      (
        ver[1] == 6 &&
        (
          ver[2] < 2 ||
          (ver[2] == 2 && ver[3] < 63)
        )
      )
    )
  )
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      'Product            : Adobe Download Manager\n' +
      'Path               : ' + path + '\n' +
      'Installed version  : ' + version + '\n' +
      'Fixed version      : 1.6.2.63\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port:port);
  exit(0);
}
exit(0, "Adobe Download Manager version "+version+" is installed and thus not affected.");
