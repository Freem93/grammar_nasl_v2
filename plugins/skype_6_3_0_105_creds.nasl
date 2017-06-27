#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(66695);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/12 17:12:47 $");

  script_bugtraq_id(58519, 58805);
  script_osvdb_id(91459, 91974);

  script_name(english:"Skype < 6.3.0.105 Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks file version of Skype.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote Skype client is potentially affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Skype installed on the remote host is earlier than
6.3.0.105 and is therefore potentially affected by the following
vulnerabilities :

  - An error exists related to the Click to Call Service
    (c2c_service.exe) that could allow a local attacker to
    cause arbitrary DLL files to be loaded, thus allowing
    code execution.

  - Several other unspecified errors exist.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2013/Mar/94");
  script_set_attribute(attribute:"see_also", value:"http://blogs.skype.com/2013/03/14/skype-6-3-for-windows/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Skype for Windows 6.3.0.105 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/30");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:skype:skype");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");


get_kb_item_or_exit("SMB/Registry/Enumerated");


# Detect where Skype's installed.
#
# nb: don't exit if a key isn't found -- we'll check another location later.
key = NULL;

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (!isnull(list))
{
  foreach name (keys(list))
  {
    prod = list[name];
    if (prod && prod =~ "^Skype.* [0-9]")
    {
      key = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(.+)\/DisplayName$", replace:"\1", string:name);
      key = str_replace(find:"/", replace:"\", string:key);
      break;
    }
  }
}


# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');


# Connect to remote registry.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}


# Find where it's installed.
path = NULL;

if (!isnull(key))
{
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:"InstallLocation");
    if (!isnull(item))
    {
      path = item[1];
      path = ereg_replace(pattern:"^(.+)\\$", replace:"\1\Phone", string:path);
    }

    RegCloseKey(handle:key_h);
  }
}
# - Look in alternate locations if we haven't found it yet.
if (isnull(path))
{
  key = "SOFTWARE\Skype\Phone";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"SkypePath");
    if (!isnull(value))
    {
      path = value[1];
      path = ereg_replace(pattern:"^(.+)\\[^\\\\]+$", replace:"\1", string:path);
    }
    RegCloseKey(handle:key_h);
  }
}
if (isnull(path))
{
  key = "SOFTWARE\Classes\skype\shell\open\command";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(item))
      path = ereg_replace(pattern:'^"(.+)\\\\[^\\\\"]+".*$', replace:"\1", string:item[1]);

    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  audit(AUDIT_NOT_INST, "Skype");
}
NetUseDel(close:FALSE);


# Check the version of the affected file.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\skype.exe", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

fh = CreateFile(
  file               : exe,
  desired_access     : GENERIC_READ,
  file_attributes    : FILE_ATTRIBUTE_NORMAL,
  share_mode         : FILE_SHARE_READ,
  create_disposition : OPEN_EXISTING
);
if (isnull(fh))
{
  NetUseDel();
  audit(AUDIT_UNINST, "Skype");
}

ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();

file = (share-'$')+":"+exe;

# Check the version number.
if (!isnull(ver))
{
  version = join(ver, sep:".");
  fixed_version = "6.3.0.105";

  # nb: we're checking the file version, not the user-friendly version.
  if (ver_compare(ver:ver, fix:fixed_version) == -1)
  {
    if (report_verbosity > 0)
    {
      report =
        '\n  File              : ' + file +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fixed_version + '\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
  else audit(AUDIT_INST_PATH_NOT_VULN, "Skype", version, path);
}
else audit(AUDIT_VER_FAIL, (share-'$')+":"+exe);
