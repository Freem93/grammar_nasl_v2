#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51395);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/12 17:12:43 $");

  script_cve_id("CVE-2010-2603");
  script_bugtraq_id(45434);
  script_osvdb_id(69928);
  script_xref(name:"Secunia", value:"42657");

  script_name(english:"BlackBerry Desktop Software < 6.0.1 Database Backup File Password Brute Force Weakness");
  script_summary(english:"Checks the version of DesktopMgr.exe or Rim.Desktop.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a program that uses a weak password
to encrypt data.");

  script_set_attribute(attribute:"description", value:
"The version of BlackBerry Desktop Software installed on the remote
host is older than version 6.0.1. Such versions use a weak password to
encrypt backup files, which makes it possible for a local user to
decrypt backup files via a brute-force attack.");

  script_set_attribute(attribute:"see_also", value:"http://www.blackberry.com/btsc/KB24764");
  script_set_attribute(attribute:"solution", value:"Upgrade to BlackBerry Desktop Software 6.0.1 or later.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/30");

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
include("smb_func.inc");
include("misc_func.inc");
include("audit.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Connect to the appropriate share.
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

# Check whether it's installed.
path = NULL;
bins = make_list("DesktopMgr.exe","Rim.Desktop.exe");

key = "SOFTWARE\Research in Motion\Common\Installations\Desktop";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Directory");
  if (!isnull(value))
  {
    path = value[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, "BlackBerry Desktop Software is not installed.");
}

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to "+share+" share.");
}

versionfail = TRUE;

foreach bin (bins)
{
  # Check the version of the main exe.
  exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\"+bin, string:path);

  fh = CreateFile(
    file:exe,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  ver = NULL;
  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);
    CloseFile(handle:fh);
    if (!isnull(ver))
    {
      versionfail = FALSE;
      break;
    }
  }
}
NetUseDel();

# Check the version number.
if (!isnull(ver))
{
  version = join(ver,sep:".");
  fixed_version = "6.0.1";

  # Only flag versions >= 4.7 and < 6.0.1
  if (
    (ver[0] > 4 || (ver[0] == 4 && ver[1] >= 7)) &&
    (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
  )
  {
    if (report_verbosity > 0)
    {
        report =
          '\n  Path               : ' + path          +
          '\n  Installed version  : ' + version       +
          '\n  Fixed version      : ' + fixed_version + '\n';
        security_note(port:port, extra:report);
    }
    else security_note(port);
    exit(0);
  }
  else exit(0, "BlackBerry Desktop Software version "+version+" is installed and not vulnerable.");
}

if (versionfail == TRUE) exit(0, "Couldn't find "+bins[0]+" or "+bins[1]+" in '"+path+"'.");
else exit(1, "Couldn't get version of "+bins[0]+" or "+bins[1]+" in '"+path+"'.");
