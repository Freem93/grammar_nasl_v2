#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50598);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/17 15:15:44 $");

  script_bugtraq_id(38667);
  script_osvdb_id(62913);
  script_xref(name:"Secunia", value:"38875");

  script_name(english:"Skype Extras Manager (skypePM.exe) skype-plugin: URI Arbitrary XML File Deletion (credentialed check)");
  script_summary(english:"Checks file version of Skype.exe");

  script_set_attribute(attribute:"synopsis", value:"The remote Skype client allows deletion of arbitrary XML files.");
  script_set_attribute(attribute:"description", value:
"According to its timestamp, the version of Skype installed on the
remote host likely includes a version of the Skype Extras Manager
(skypePM.exe) that has a flaw in its handling of the 'skype-plugin:'
protocol.

If an attacker can trick a user on the affected system into clicking
on a specially crafted link, arbitrary '.xml' files on the affected
system could be deleted, subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-028/");
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/bugtraq/2010/Mar/115"
  );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Skype 4.2.0.169 or later as that is reported to address the
issue.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/15");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:skype:skype");
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


include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");


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
  exit(1, "Can't connect to IPC$ share.");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to the remote registry.");
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
  exit(0, "Skype is not installed.");
}
NetUseDel(close:FALSE);


# Check the version of the affected file.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\skype.exe", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to "+share+" share.");
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
  exit(0, "Failed to open '"+(share-'$')+":"+exe+"'.");
}

ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();


# Check the version number.
if (!isnull(ver))
{
  version = join(ver, sep:".");
  fixed_version = "4.2.0.169";

  # nb: we're checking the file version, not the user-friendly version.
  if (ver_compare(ver:ver, fix:fixed_version) == -1)
  {
    if (report_verbosity > 0)
    {
      report =
        '\n  File              : ' + (share-'$')+":"+exe +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fixed_version + '\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0);
  }
  else exit(0, "Skype version "+version+" is installed and thus is not affected.");
}
else exit(1, "Couldn't get file version of '"+(share-'$')+":"+exe+"'.");
