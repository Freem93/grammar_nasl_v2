#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(46784);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/03 20:40:06 $");

  script_cve_id("CVE-2010-0392");
  script_bugtraq_id(40387);
  script_osvdb_id(61866);
  script_xref(name:"Secunia", value:"38262");

  script_name(english:"TheGreenBow VPN Client TGB File OpenScriptAfterUp Parameter Local Overflow");
  script_summary(english:"Checks the version of TheGreenBow VPN client");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a VPN client that is affected by a
stack-based buffer overflow vulnerability.");

  script_set_attribute(attribute:"description", value:
"The remote Windows host contains TheGreenBow VPN client, an IPsec VPN
client.

The installed version of TheGreenBow VPN Client is earlier than
4.65.003 or is an unpatched instance of 4.65.003. As such, it is
reportedly affected by a local stack based buffer overflow caused by a
boundary error when processing an overly long 'OpenScriptAfterUp'
parameter of the 'tgb' policy file.

An attacker, exploiting this flaw, could potentially execute arbitrary
code subject to the privileges of the user running the affected
application.");

  script_set_attribute(attribute:"see_also", value:"http://www.senseofsecurity.com.au/advisories/SOS-10-001");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2010/Jan/189");
  script_set_attribute(attribute:"see_also", value:"http://www.thegreenbow.com/download.php?id=1000150");
  script_set_attribute(attribute:"solution", value:
"Upgrade to TheGreenBow VPN client version 4.6.5.3 if necessary and
apply the patch referenced in the vendor's advisory.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/02");

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
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
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

# Attempt to first detect the install path from the
# HKLM\SOFTWARE\TheGreenBow\TheGreenBow VPN
path = NULL;

reg = "SOFTWARE\TheGreenBow\TheGreenBow VPN";
key_h = RegOpenKey(handle:hklm, key:reg, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(item)) path = item[1];

  RegCloseKey(handle:key_h);
}

if (isnull(path))
{
  # Look for the app in the uninstall KB
  list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
  if (isnull(list)) exit(1, "The 'SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName' KB items are missing.");

  foreach name (keys(list))
  {
    prod = list[name];
    if (prod && "TheGreenBow VPN Client" >< prod)
    {
      installstring = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
      installstring = str_replace(find:"/", replace:"\", string:installstring);
      break;
    }
  }

  if (!isnull(installstring))
  {
    key_h = RegOpenKey(handle:hklm, key:installstring, mode:MAXIMUM_ALLOWED);

    if (!isnull(key_h))
    {
      item = RegQueryValue(handle:key_h, item:"Path");
      if (!isnull(item)) path = item[1];
      else
      {
        item = RegQueryValue(handle:key_h, item:"DisplayIcon");
        if (!isnull(item))  path = ereg_replace(pattern:"([A-Za-z]:.*)\\vpnconf.exe", replace:"\1", string:item[1]);
      }

      RegCloseKey(handle:key_h);
    }
  }
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, "The TheGreenBow VPN client does not appear to be installed.");
}
NetUseDel(close:FALSE);


# Determine the version from the executable
ver = NULL;

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe   = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\vpnconf.exe", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc !=1 )
{
  NetUseDel();
  exit(1, "Can't connect to share '"+share+"' share.");
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
  exit(1, "Unable to access TheGreenBow VPN client executable '"+(share-'$')+":"+exe+"'.");
}

ver = GetFileVersion(handle:fh);
if (isnull(ver))
{
  CloseFile(handle:fh);
  NetUseDel();
  exit(1, "Failed to get file version of '"+exe+"' on share " + share + ".");
}

vuln=FALSE;

if (
  ver[0] < 4 ||
  (
    ver[0] == 4 &&
    (
      ver[1] < 6 ||
      (
        ver[1] == 6 &&
        (
          ver[2] < 5 ||
          (ver[2] == 5 && ver[3] < 3)
        )
      )
    )
  )
)
{
  vuln = TRUE;
  report =
    '\n  Path              : ' + path +
    '\n  EXE               : vpnconf.exe '+
    '\n  Installed version : ' + join(sep:'.', ver) +
    '\n  Fixed version     : 4.6.5.3 (Patched Version MD5 : 63c6c93e99578b40296812f090b09628)';
}
else if (ver[0] == 4 && ver[1] == 6 && ver[2] == 5 && ver[3] == 3)
{
  buff = "";
  vpnconf_patched_md5 = '63c6c93e99578b40296812f090b09628';

  fsize = GetFileSize(handle:fh);
  chunk = 10320;
  ofs = 0;
  while (ofs < fsize)
  {
    buff += ReadFile(handle:fh, length:chunk, offset:ofs);
    ofs += chunk;
  }

  if (strlen(buff) < fsize)
  {
    CloseFile(handle:fh);
    NetUseDel();
    exit(1, "Failed to read all of '" + (share-'$')+":"+exe + "'.");
  }

  vpnconf_md5 = hexstr(MD5(buff));
  if (vpnconf_md5 != vpnconf_patched_md5)
  {
    vuln = TRUE;
    report =
      '\nNessus detected version 4.6.5.3 of TheGreenBow VPN client, but based ' +
      '\non the MD5 hash of the contents of the file, it is an unpatched ' +
      '\nversion : '+
      '\n  Path      : ' + path +
      '\n  EXE       : vpnconf.exe' +
      '\n  MD5       : ' + vpnconf_md5 +
      '\n  Fixed MD5 : 63c6c93e99578b40296812f090b09628';
  }
}

#Clean Up
CloseFile(handle:fh);
NetUseDel();

if (vuln)
{
  if (report_verbosity > 0)
    security_hole(port:port, extra:report);
  else
    security_hole(port);
  exit(0);
}
exit(0, "The remote host is not affected because TheGreenBow VPN client version "+join(sep:'.', ver)+" is installed.");
