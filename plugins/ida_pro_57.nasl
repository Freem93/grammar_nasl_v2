#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47828);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/01/12 17:12:45 $");

  script_bugtraq_id(41201);
  script_osvdb_id(66016);

  script_name(english:"IDA Pro QNX File Loader Denial of Service");
  script_summary(english:"Checks the version of IDA Pro");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by a denial
of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IDA Pro, an interactive disassembler, installed on the
remote host is older than 5.7. Such versions are reportedly affected
by an integer overflow when loading QNX files.

By tricking a user into loading a specially crafted QNX file in IDA
Pro, it may be possible for the attacker to cause the loader to go
into an infinite loop, consuming 100% of the CPU and resulting in a
denial of service.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/512052/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.hex-rays.com/idapro/57/index.htm");
  script_set_attribute(attribute:"solution", value:"Upgrade to IDA Pro 5.7 or later.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/26");

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

get_kb_item_or_exit("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/IDA Pro_is1/DisplayName");

# Connect to the appropriate share.
get_kb_item_or_exit("SMB/Registry/Enumerated");
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


# Check whether it's installed.
path = NULL;

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\IDA Pro_is1";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"InstallLocation");
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
  exit(0, "IDA Pro is not installed.");
}


# Check the version of the main exe.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\idag.exe", string:path);
NetUseDel(close:FALSE);
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
if (isnull(fh))
{
  NetUseDel();
  exit(0, "Failed to open '"+path+"\idag.exe'.");
}
ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();

# Check the version number.
if (!isnull(ver))
{
  version = join(ver, sep:".");
  fixed_version = "5.7";

  if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
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
  exit(0, "IDA Pro version "+version+" is installed and not vulnerable.");
}
else exit(1, "Couldn't get file version of '"+path+"\idag.exe'.");
