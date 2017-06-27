#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21746);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/01/12 17:12:46 $");

  script_name(english:"Opera Browser Detection");
  script_summary(english:"Checks for Opera");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host contains an alternative web browser.");
 script_set_attribute(attribute:"description", value:
"Opera, an alternative web browser, is installed on the remote Windows
host.");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/products/desktop/");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

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

# Detect which registry key Opera's install used.
#
# nb: don't exit if a key isn't found -- we'll check another location later.
list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (isnull(list))
  list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Wow6432Node/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
key = NULL;
foreach name (keys(list))
{
  prod = list[name];
  if (prod && prod =~ "^Opera($| (Stable )?[0-9])")
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

# Determine where it's installed.
path = NULL;

if (!isnull(key))
{
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    # nb: version 9.x. or greater
    item = RegQueryValue(handle:key_h, item:"InstallLocation");
    if (!isnull(item))
    {
      path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:item[1]);

      # nb: even more recent; add {version} to path
      # Uninstall registry entry contains the latest-installed /
      # 'in-use' version
      item = RegQueryValue(handle:key_h, item:"DisplayVersion");
      if (!isnull(item))
      {
        version_pieces = split(item[1], sep:".", keep:FALSE);
        if (version_pieces[0] >= 15)
          path = path + "\" + item[1];
      }
    }

    if (isnull(path))
    {
      # nb: recent version 8.x.
      item = RegQueryValue(handle:key_h, item:"UninstallString");
      if (!isnull(item))
      {
        if ("\uninst" >< item[1])
          path = ereg_replace(pattern:"^([^ ]*)\\uninst.*$", replace:"\1", string:item[1]);
      }
    }
    RegCloseKey(handle:key_h);
  }
}
# - Look for older ones if we haven't found it yet.
if (isnull(path))
{
  key = "SOFTWARE\Netscape\Netscape Navigator\5.0, Opera\Main";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:"Install Directory");
    if (!isnull(item)) path = item[1];

    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  audit(AUDIT_NOT_INST, "Opera");
}

# Determine its version from the executable itself.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe   = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Opera.exe", string:path);
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

build = "";
version = "";
version_ui = "";

if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  if (!isnull(ver))
    version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);

  fsize = GetFileSize(handle:fh);
  if (fsize < 90000) off = 0;
  else off = fsize - 90000;

  vs_version_info = mk_unicode(str:"VS_VERSION_INFO");
  while (fsize > 0 && off <= fsize)
  {
    data = ReadFile(handle:fh, length:16384, offset:off);
    if (strlen(data) == 0) break;

    if (vs_version_info >< data)
    {
      table = strstr(data, vs_version_info);

      file_ver = "";
      fileversion = mk_unicode(str:"FileVersion");
      if (fileversion >< table)
      {
        i = stridx(table, fileversion) + strlen(fileversion);
        while (i<strlen(table) && !ord(table[i])) i++;
        while (i<strlen(table) && ord(table[i]))
        {
          file_ver += table[i];
          i += 2;
        }
      }

      # nb: in >= 15.x product version is the same as
      # file version
      prod_ver = "";
      productversion = mk_unicode(str:"ProductVersion");
      if (productversion >< table)
      {
        i = stridx(table, productversion) + strlen(productversion);
        while (i<strlen(table) && !ord(table[i])) i++;
        while (i<strlen(table) && ord(table[i]))
        {
          prod_ver += table[i];
          i += 2;
        }
      }

      if (prod_ver)
      {
        version_ui = prod_ver;

        if (file_ver)
        {
          matches = eregmatch(pattern:"^([0-9]+) *\((.+)\) *$", string:file_ver);
          if (!isnull(matches))
          {
            build = matches[1];
            version_ui += " " + matches[2];
          }
          else build = file_ver;
        }
      }

      break;
    }
    else off += 16383;
  }

  CloseFile(handle:fh);
}
NetUseDel();

# Save and report the version number and installation path.
if (!isnull(version) && version != "" && !isnull(path))
{
  info = "";
  kb_base = "SMB/Opera";

  set_kb_item(name:kb_base+"/Version", value:version);
  if (!isnull(version_ui) && version_ui != "")
  {
    set_kb_item(name:kb_base+"/Version_UI", value:version_ui);
    version_report = version_ui;
  }
  else version_report = version;
  info += '  Version : ' + version_report + '\n';

  # Add flag for 12.x which is still being patched
  # Update regex if 13.x/14.x becomes reality
  # If a supported classic branch goes away - remove this code
  if (version =~ "^12\.")
    set_kb_item(name:kb_base+"/supported_classic_branch", value:TRUE);

  if (!isnull(build) && build != "")
  {
    set_kb_item(name:kb_base+"/Build", value:build);
    info += '  Build   : ' + build + '\n';
  }
  set_kb_item(name:kb_base+"/Path",    value:path);

  register_install(
    app_name:"Opera",
    path:path,
    version:version,
    extra:make_array('Build', build),
    cpe:"cpe:/a:opera:opera_browser");

  info += '  Path    : ' + path + '\n';

  if (report_verbosity)
  {
    report = string(
      "\n",
      info
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
