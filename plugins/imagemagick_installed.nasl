#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38949);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/03/22 14:08:09 $");

  script_name(english:"ImageMagick Detection");
  script_summary(english:"Checks for ImageMagick installs.");

  script_set_attribute(attribute:"synopsis", value:
"An image editing application is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"ImageMagick is installed on the remote Windows host. ImageMagick is an
application for creating, editing, and composing bitmap images.");
  script_set_attribute(attribute:"see_also", value:"https://www.imagemagick.org/script/index.php");
  script_set_attribute(attribute:"solution", value:
"Check that the use of ImageMagick is in agreement with your
organization's security and acceptable use policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:imagemagick:imagemagick");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("smb_reg_query.inc");
include("install_func.inc");
include("spad_log_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app = "ImageMagick";
path = NULL;
paths = NULL;
older_versions = FALSE;

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");

if (!isnull(list))
{
  foreach name (keys(list))
  {
    prod = list[name];

    if (!isnull(prod) && "ImageMagick" >< prod)
    {
      uninstall_location_kb = name - "/DisplayName" + "/InstallLocation";
      path = get_kb_item(uninstall_location_kb);
      paths[prod] = path;
    }
  }
}

# Bad install might not have the uninstall key
# Check the base key if uninstall was blank
if(isnull(paths))
{
  registry_init();
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  base_key = "SOFTWARE\ImageMagick";
  subkeys = get_registry_subkeys(handle:hklm, key:base_key);
  if (!isnull(subkeys))
  {
    foreach subkey (subkeys)
    {
      # Are are two subkeys at this point. We want to check both.
      key = base_key + "\" + subkey;

      path = get_registry_value(handle:hklm, item:key+"\Q:8\BinPath");
      if (!isnull(path))
        paths['ImageMagick '+subkey+'Q:8'] = path;

      path = get_registry_value(handle:hklm, item:key+"\Q:16\BinPath");
      if (!isnull(path))
        paths['ImageMagick '+subkey+'Q:16'] = path;
    }
  }
  RegCloseKey(handle:hklm);
  close_registry(close:FALSE);
}
if(isnull(paths)) audit(AUDIT_NOT_INST, app);

foreach prod (keys(paths))
{
  # depending on the version we need to check a different file
  foreach file (make_list("magick.exe", "compare.exe", "display.exe", "stream.exe"))
  {
    ret = FALSE;
    exe = paths[prod] + "\" + file;
    fver = hotfix_get_fversion(path:exe);

    ret = hotfix_handle_error(error_code:fver['error'], file:exe, appname:app, exit_on_fail:FALSE);
    if(ret)
    {
      spad_log(message:ret);
      continue;
    }

    # Its possible the file version is off
    # Lets check it against the product verison
    pver = hotfix_get_pversion(path:exe);

    ret = hotfix_handle_error(error_code:pver['error'], file:exe, appname:app, exit_on_fail:FALSE);
    if(ret)
    {
      spad_log(message:ret);
      continue;
    }

    # If we got both then we are good.
    if(fver['error'] == 0 && pver['error'] == 0)
      break;
  }

  full_version = NULL;

  # If we failed to get either versions
  # get it from the DisplayName
  if(fver['error'] != 0 || pver['error'] != 0)
  {
    matches = NULL;
    matches = pregmatch(pattern:"ImageMagick ([0-9.-]+) ", string:prod);
    if(isnull(matches))
    {
      spad_log(message:'Unable to parse product name \'' + prod + '\'.');
      continue;
    }
    full_version = matches[1];
  }
  # If the major versions dont match between the
  # file and product verison, get the DisplayName version
  else if(fver['value'][0] != substr(pver['value'],0,0))
  {
    matches = NULL;
    matches = pregmatch(pattern:"ImageMagick ([0-9.-]+) ", string:prod);
    if(isnull(matches))
    {
      spad_log(message:'Unable to parse product name \'' + prod + '\'.');
      continue;
    }
    full_version = matches[1];
  }
  else
  {
    full_version = str_replace(string:join(sep:"-", fver["value"]), find:"-", replace:".", count:2);
  }

  if(!isnull(full_version) && "-" >< full_version)
  {
    # Lets get the components
    parts = pregmatch(pattern:"([0-9.]+)-([0-9]+)", string:full_version);
    # This should never error, but if it does lets continue to the next
    if(isnull(parts))
    {
      spad_log(message:'Unable to parse full version \'' + full_version + '\'.');
      continue;
    };

    register_install(
      app_name       : app,
      path           : paths[prod],
      version        : parts[1],
      display_version: full_version,
      cpe            : "cpe:/a:imagemagick:imagemagick",
      extra_no_report: make_array("build",parts[2]));
  }
}

hotfix_check_fversion_end();

report_installs(app_name:app);
