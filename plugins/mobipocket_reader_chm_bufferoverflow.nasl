#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(59108);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/12 17:12:45 $");

  script_bugtraq_id(53200);
  script_osvdb_id(81328);
  script_xref(name:"EDB-ID", value:"18774");

  script_name(english:"Mobipocket Reader CHM File Handling Remote Overflow");
  script_summary(english:"Checks for Mobipocket Reader");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an eBook reader that is affected by a
buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"All versions of Mobipocket Reader are potentially affected by a
stack-based buffer overflow vulnerability.

The application does not properly validate user input and can allow
crafted 'CHM' files to either crash the application or execute
arbitrary code if an attack is successful.

Note that Mobipocket Reader is no longer supported which implies no
new security patches will be released.");
  script_set_attribute(attribute:"see_also", value:"http://shinnai.altervista.org/exploits/SH-018-20120423.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Apr/255");
  script_set_attribute(attribute:"see_also", value:"http://www.mobipocket.com/en/DownloadSoft/default.asp");
  script_set_attribute(attribute:"solution", value:"Remove the software as it is no longer supported.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:amazon:mobipocket_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("smb_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated"))
  audit(AUDIT_KB_MISSING, "SMB/Registry/Enumerated");

function mk_unicode(str)
{
  local_var i, l, null, res;

  l = strlen(str);
  null = '\x00';
  res = "";

  for (i=0; i<l; i++)
    res += str[i] + null;

  return res;
}


# Detect which registry key Mobipocket Reader's install used.
requested_kb_list = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName";
list = get_kb_list(requested_kb_list);
if (isnull(list)) audit(AUDIT_KB_MISSING, requested_kb_list);
key = NULL;
foreach name (keys(list))
{
  prod = list[name];
  if (prod && prod =~ "^Mobipocket Reader($| [0-9])")
  {
    key = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(.+)\/DisplayName$", replace:"\1", string:name);
    key = str_replace(find:"/", replace:"\", string:key);
    break;
  }
}


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
  audit(AUDIT_SHARE_FAIL, "IPC$");
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}


# Get version from registry
display_version = NULL;
path = NULL;

if (!isnull(key))
{
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:"DisplayVersion");
    if (!isnull(item))
      display_version = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:item[1]);

    RegCloseKey(handle:key_h);
  }

  # Get path info from another key
  key_h = RegOpenKey(handle:hklm, key:"SOFTWARE\MobiPocket.com\Mobipocket Reader", mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:"PCReaderFullName");
    if (!isnull(item))
      path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:item[1]);

    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  audit(AUDIT_NOT_INST, "Mobipocket Reader");
}


# Determine if this is Mobipocket Reader's 'reader.exe' from the executable itself.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe   = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

found_exe = FALSE;

if (!isnull(fh))
{
  fsize  = GetFileSize(handle:fh);
  off    = 3203072;
  cutoff = 3219456;

  string1 = mk_unicode(str:"oeb:database?name=mobipocket_history");
  string2 = mk_unicode(str:"mobipocketDrawingSurface");
  string3 = mk_unicode(str:"application/x-mobipocket");

  while (fsize > 0 && off <= cutoff)
  {
    data = ReadFile(handle:fh, length:16384, offset:off);
    if (strlen(data) < 1) break;

    if (string1 >< data)
      string1_found = TRUE;

    if (string2 >< data)
      string2_found = TRUE;

    if (string3 >< data)
      string3_found = TRUE;

    if (string1_found && string2_found && string3_found)
    {
      found_exe = TRUE;
      break;
    }

    off += 16383;
  }
  CloseFile(handle:fh);
}
NetUseDel();


# Save and report the version number and installation path.
if (!isnull(path) && found_exe)
{
  info = "";
  kb_base = "SMB/MobipocketReader";

  set_kb_item(name:kb_base+"/Path",    value:path);
  info += '  Path              : ' + path + '\n';

  if (!isnull(display_version))
  {
    # Split out build number
    pieces = split(display_version, sep:".", keep:FALSE);
    version = pieces[0] + '.' + pieces[1];
    set_kb_item(name:kb_base+"/Version", value:version);

    if (!isnull(pieces[2]))
    {
      build = pieces[2];
      set_kb_item(name:kb_base+"/Build", value:build);
      version_report = version + ' Build ' + build;
    }
    else version_report = version;
  }
  else version_report = 'Unknown';

  info += '  Installed version : ' + version_report + '\n';

  if (report_verbosity)
  {
    report = '\n' + info;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_NOT_INST, "Mobipocket Reader");
