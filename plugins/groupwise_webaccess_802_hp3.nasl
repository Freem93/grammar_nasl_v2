#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56407);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/02/03 17:40:02 $");

  script_name(english:"Novell GroupWise WebAccess Directory.Item Parameters XSS");
  script_summary(english:"Checks version of GWINTER.exe");

  script_cve_id("CVE-2011-2661");
  script_bugtraq_id(49773);
  script_osvdb_id(75773);

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a cross-site
scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Novell GroupWise installed on the remote Windows host
is earlier than 8.0.2 HP3. It is, therefore, reportedly affected by a
cross-site scripting vulnerability because the application fails to
sanitize user-supplied input to the 'Directory.Item.name' and
'Directory.Item.displayName' parameters.

A remote attacker may be able to exploit this vulnerability to execute
arbitrary script code in the browser of an unsuspecting user in the
context of the affected site.");

  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/viewContent.do?externalId=7009214");
  script_set_attribute(attribute:"solution", value:"Apply 8.02 Hot Patch 3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/06");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:groupwise_webaccess");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:novell:groupwise");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("groupwise_webaccess_accessible.nasl", "smb_hotfixes.nasl");
  script_require_keys("Settings/ParanoidReport", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();
#if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc)  exit(1, "Can't open socket on port "+port+".");

#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

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

# Find where it's installed.
path = NULL;
servicename = NULL;

# First get the WebAccess Servicename

key = "SOFTWARE\NOVELL\GroupWise WebAccess\ServiceNames";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[0]; ++i)
  {
    value = RegEnumValue(handle:key_h, index:i);
    # WebAccess (WEBAC80A)
    if (strlen(value[1]) && "WebAccess" >< value[1] )
    {
      servicename = value[1];
      break;
    }
  }
  RegCloseKey(handle:key_h);
}

if (isnull(servicename))
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(1, "It was not possible to determine GroupWise WebAccess servicename.");
}

# Now extract path from EventMessageFile location.

key = "SYSTEM\CurrentControlSet\Services\Eventlog\Application\\"+ servicename;
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"EventMessageFile");
  if (!isnull(value))
  {
    path = value[1];
    # extract the path from EventMessageFile value.
    # e.g. "c:\Program Files\Novell\GroupWise Server\WebAccess\gwwa1en.dll"
    path = ereg_replace(pattern:'["]*'+"([A-Za-z]:.*)\\[^\\]+" + '["]*', replace:"\1", string:path);
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, "GroupWise WebAccess is not installed.");
}
NetUseDel(close:FALSE);

# Grab the file version of GroupWise WebAccess Agent.
share = ereg_replace(pattern:'["]*([A-Za-z]):.*', replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\GWINTER.exe", string:path);

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
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
NetUseDel();

if (isnull(ver))
  exit(1, "Couldn't get the file version of '"+(share-'$')+":"+exe+"'.");

# Check the version number.
version = join(ver, sep:".");
if (ver_compare(ver:version, fix:'8.0.2.16933') == -1)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 8.0.2.16933\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else exit(0,"GroupWise WebAccess version "+ version + " is installed and hence is not affected.");
