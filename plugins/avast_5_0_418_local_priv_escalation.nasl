#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44876);
  script_version("$Revision: 1.10 $");
 script_cvs_date("$Date: 2016/05/04 14:21:29 $");

  script_cve_id("CVE-2010-0705");
  script_bugtraq_id(38363);
  script_osvdb_id(62510);

  script_name(english:"avast! Professional Edition < 5.0.418 Local Privilege Escalation");
  script_summary(english:"Checks version of avast! Professional Edition");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by a
local privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running avast! Professional Edition. The
installed version of this software is potentially affected by a local
privilege escalation vulnerability because the 'aavmker4.sys' driver
fails to sufficiently sanitize user-supplied input passed via a
specially crafted IOCTL request.");
  script_set_attribute(attribute:"see_also", value:"http://trapkit.de/advisories/TKADV2010-003.txt");
  script_set_attribute(attribute:"see_also",value:"http://forum.avast.com/index.php?topic=55484.0");
  script_set_attribute(attribute:"solution", value:"Upgrade to Avast! Professional Edition 5.0.418 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:avast:avast_antivirus_professional");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139,445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");

# Connect to the appropriate share.
name   = kb_smb_name();
port   = kb_smb_transport();
#if (!get_port_state(port)) exit(1, "Port "+port+" is not open.");
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc) exit(1, "Can't open socket on port "+port+".");

#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

# Connect to the remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to the remote registry.");
}

# Grab the installation path and product info from the registry.
path = NULL;
prod = NULL;

#Avast 4.x
key = "Software\ALWIL Software\Avast\4.0";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Avast4ProgramFolder");
  if (!isnull(value)) path = value[1];

  value = RegQueryValue(handle:key_h, item:"Product");
  if (!isnull(value)) prod = value[1];

  RegCloseKey(handle:key_h);
}
#Avast 5.x
else
{
  key = "SOFTWARE\ALWIL Software\Avast\5.0";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"ProgramFolder");
    if (!isnull(value)) path = value[1];

    value = RegQueryValue(handle:key_h, item:"Product");
    if (!isnull(value)) prod = value[1];

    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);

# If its installed...
ver = NULL;

if (!isnull(path) && !isnull(prod) && (prod == "ais" || prod == "av_pro"))
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  if (prod == "av_pro")
    dll = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\aswEngin.dll",string:path);
  else
    dll = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\aswEngLdr.dll",string:path);

  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, "Can't connect to '"+share+"' share.");
  }

  fh = CreateFile(
    file:dll,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (isnull(fh))
  {
    NetUseDel();
    exit(1, "Can't open the file '"+(share-'$')+":"+dll+"'.");
  }

  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}

# Clean up.
NetUseDel();

if (!isnull(ver))
{
  version = string(ver[0], ".", ver[1], ".", ver[2]);
  fixed_version = "5.0.418";

  if (
    (
      ver[0] == 4 &&
      (
        ver[1] < 8 ||
        (ver[1] == 8 && ver[2] <= 1368)
      )
    ) ||
    (ver[0] == 5 && ver[1] == 0 && ver[2] < 418)
  )
  {
    if (report_verbosity > 0)
    {
      report =
        '\n  Product           : Avast! Professional Edition'+
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fixed_version + '\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
  }
  else exit(0, "Avast! Professional Edition version " + version + " is not affected.");
}
