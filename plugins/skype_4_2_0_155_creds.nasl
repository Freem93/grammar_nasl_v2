#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45061);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/01/12 17:12:47 $");

  script_bugtraq_id(38699);
  script_osvdb_id(62853);
  script_xref(name:"Secunia", value:"38908");

  script_name(english:"Skype skype: URI Handling /Datapath Argument Injection Settings Manipulation (credentialed check)");
  script_summary(english:"Checks file version of Skype.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote Skype client is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its timestamp, the version of Skype installed on the
remote Windows host fails to sanitize input in its URI handler to its
'/Datapath' argument, which specifies the location of the Skype
configuration files and security policy.

If an attacker can trick a user on the affected system into clicking
on a specially crafted link, the client could be made to use a
Datapath location on a remote SMB share. In turn, this could lead to
man-in-the-middle attacks or the disclosure of sensitive information,
such as call history associated with the user.");
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.security-assessment.com/files/advisories/Skype_URI_Handling_Vulnerability.pdf"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/510017/30/0/threaded"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://developer.skype.com/WindowsSkype/ReleaseNotes"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://share.skype.com/sites/garage/2010/03/10/ReleaseNotes_4.2.0.155.pdf"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Skype 4.2.0.155 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/15");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:skype:skype");
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
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


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
  exit(1, "Can't connect to remote registry.");
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


# Check the version of the main exe.
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

ver = NULL;
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
NetUseDel();


# Check the version number.
if (!isnull(ver))
{
  fixed_version = "4.2.0.155";
  version = join(ver, sep:".");

  fix = split(fixed_version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
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
    else if (ver[i] > fix[i])
      break;

  exit(0, "Skype version "+version+" is installed and not vulnerable.");
}
else exit(1, "Couldn't get file version of '"+(share-'$')+":"+exe+"'.");
