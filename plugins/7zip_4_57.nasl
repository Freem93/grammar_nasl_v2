#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31607);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/01/12 17:12:42 $");

  script_cve_id("CVE-2008-6536");
  script_bugtraq_id(28285);
  script_osvdb_id(43649);
  script_xref(name:"Secunia", value:"29434");

  script_name(english:"7-Zip < 4.57 Archive Handling Unspecified Issue");
  script_summary(english:"Checks version of 7zip.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a program that is affected by an
unspecified vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a version of the open source 7-Zip file
archiver and included in third-party products such as Knownsoft's
Turbo Searcher.

The version of 7-Zip installed on the remote host reportedly is
affected by an as-yet unspecified vulnerability involving archive
handling.");
  script_set_attribute(attribute:"see_also", value:"http://www.cert.fi/haavoittuvuudet/joint-advisory-archive-formats.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to 7Zip 4.57 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:7-zip:7-zip");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if (!smb_session_init()) exit(0);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) {
  NetUseDel();
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


# Make sure it's installed.
paths =  make_array();

# - 7-Zip itself
prod = "7-Zip";
key = "SOFTWARE\7-Zip";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(value)) paths[prod] = value[1];

  RegCloseKey(handle:key_h);
}
# - Turbo Searcher
prod = "Turbo Searcher";
key = "SOFTWARE\Classes\folder\shellex\ContextMenuHandlers\Turbo Searcher";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value)) clsid = value[1];

  RegCloseKey(handle:key_h);

  if (!isnull(clsid))
  {
    key = "SOFTWARE\Classes\CLSID\" + clsid + "\InprocServer32";
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      value = RegQueryValue(handle:key_h, item:NULL);
      if (!isnull(value)) paths[prod] = ereg_replace(pattern:"^(.+)\\[^\\]+\.dll", replace:"\1", string:value[1]);

      RegCloseKey(handle:key_h);
    }
  }
}
RegCloseKey(handle:hklm);
if (max_index(keys(paths)) == 0)
{
  NetUseDel();
  exit(0);
}


# Check the version of 7z.exe.
info = "";

foreach prod (keys(paths))
{
  path = paths[prod];

  # Check the version of the main exe.
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\7z.exe", string:path);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(0);
  }

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
  }

  # Check the version number.
  if (!isnull(ver))
  {
    fix = split("4.57", sep:'.', keep:FALSE);
    for (i=0; i<max_index(fix); i++)
      fix[i] = int(fix[i]);

    for (i=0; i<max_index(ver); i++)
      if ((ver[i] < fix[i]))
      {
        version = string(ver[0], ".", ver[1]);
        info += "  - " + path + ", version " + version + '\n';
        break;
      }
      else if (ver[i] > fix[i])
        break;
  }
}
NetUseDel();


# Issue a report if any vulnerable installs were found.
if (info)
{
  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 1) s = "s of 7-Zip are";
    else s = " of 7-Zip is";

    report = string(
      "\n",
      "The following instance", s, " installed on the remote host :\n",
      "\n",
      info
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
