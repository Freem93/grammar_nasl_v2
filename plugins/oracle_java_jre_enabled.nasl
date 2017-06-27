#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65743);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/06/13 20:14:28 $");

  script_name(english:"Oracle Java JRE Enabled (Internet Explorer)");
  script_summary(english:"Checks if Oracle Java is enabled in IE");

  script_set_attribute(attribute:"synopsis", value:"The remote host has Oracle Java JRE enabled for Internet Explorer.");
  script_set_attribute(attribute:"description", value:"Oracle Java JRE is enabled in Internet Explorer.");
  script_set_attribute(attribute:"solution", value:"Apply Microsoft 'Fix it' 50994 unless Java is needed.");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/2751647");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright("This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("sun_java_jre_installed.nasl", "google_chrome_installed.nasl", "opera_installed.nasl", "mozilla_org_installed.nasl");
  script_require_keys("SMB/Java/JRE/Installed");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_activex_func.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Walk up the path and check if each directory
# in the path is a reparse point.
function reparse_points_exist_in_path(check_path)
{
  local_var check_ret;

  while (check_path != '\\' && strlen(check_path) > 0)
  {
    check_ret = FindFirstFile(pattern:check_path);

    # Look for reparse point directories
    # in file attributes.
    if (!isnull(check_ret[2]) &&
      # FILE_ATTRIBUTE_DIRECTORY
      ((check_ret[2] >> 4) & 0x1) &&
      # FILE_ATTRIBUTE_REPARSE_POINT
      ((check_ret[2] >> 10) & 0x1)
    )
      return TRUE;

    check_path = ereg_replace(
      pattern:"^(.*)\\([^\\]*)?$",
      replace:"\1",
      string:check_path
    );
  }
  return FALSE;
}

function check_java_universally_disabled(handle)
{
  local_var key, res;

  key = "SOFTWARE\Oracle\JavaDeploy\WebDeployJava";
  res = get_registry_value(handle:handle, item:key);

  if (res == 'disabled') return 1;
  return 0;
}

function ie_check_java_disabled()
{
  local_var clsid, clsids, i;
  local_var hku, key_h, reginfo, subkey, key, res;
  local_var info, info2;

  info = '';
  info2 = '';
  # First check the Java CLSIDs to make sure the
  # kill bits are set
  _acx_init = TRUE;
  _acx_filenames = make_array();
  _acx_installed_clsids = make_array();
  _acx_hklm = _FCT_ANON_ARGS[0];

  clsids = make_list(
    '{8AD9C840-044E-11D1-B3E9-00805F499D93}',
    '{CAFEEFAC-0017-0000-FFFF-ABCDEFFEDCBA}',
    '{CAFEEFAC-0017-0001-FFFF-ABCDEFFEDCBA}',
    '{CAFEEFAC-0017-0002-FFFF-ABCDEFFEDCBA}',
    '{CAFEEFAC-0017-0003-FFFF-ABCDEFFEDCBA}',
    '{CAFEEFAC-0017-0004-FFFF-ABCDEFFEDCBA}',
    '{CAFEEFAC-0017-0005-FFFF-ABCDEFFEDCBA}',
    '{CAFEEFAC-0017-0006-FFFF-ABCDEFFEDCBA}',
    '{CAFEEFAC-FFFF-FFFF-FFFF-ABCDEFFEDCBA}'
  );
  foreach clsid (clsids)
  {
    if (activex_get_killbit(clsid:clsid) == 0)
    {
      info += '  ' + clsid + '\n';
    }
  }
  _acx_hklm = NULL;
  _acx_init = FALSE;

  if (info) info = 'ActiveX CLSIDs :\n' + info + '\n';

  # Next check the HKU registry keys
  hku = registry_hive_connect(hive:HKEY_USERS);
  if (isnull(hku)) return NULL;

  key_h = RegOpenKey(handle:hku, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    reginfo = RegQueryInfoKey(handle:key_h);
    if (!isnull(reginfo))
    {
      for (i=0; i < reginfo[1]; i++)
      {
        subkey = RegEnumKey(handle:key_h, index:i);
        if (subkey =~ '^S-1-5-21-[0-9\\-]+$')
        {
          key = subkey + "\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1C00";
          res = get_registry_value(handle:hku, item:key);
          if (!isnull(res) && res != 0)
            info2 += '  ' + subkey + '\n';
        }
      }
    }
    RegCloseKey(handle:key_h);
  }
  RegCloseKey(handle:hku);
  if (info2) info2 = 'User SIDs :\n' + info2;
  info += info2;

  return info;
}

function chrome_check_java_disabled(path, winver)
{
  local_var java_disabled;
  local_var fh, fsize, off, data, chunk;
  local_var pref, chromeplugins, chromesettings, i, pluginpref_start, pluginpref_end;

  java_disabled = TRUE;
  if (isnull(path)) return NULL;
  if (winver < 6)
    path = path + "\Local Settings\Application Data\Google\Chrome\User Data\Default\Preferences";
  else
    path = path + "\Local\Google\Chrome\User Data\Default\Preferences";
  pref = ereg_replace(pattern:'^[A-Za-z]:(.*)', string:path, replace:"\1");

  fh = CreateFile(
    file:pref,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  pluginpref_start = FALSE;
  pluginpref_end = FALSE;
  if (!isnull(fh))
  {
    fsize = GetFileSize(handle:fh);
    off = 0;

    # Read in the file
    while (off <= fsize)
    {
      data = ReadFile(handle:fh, length:10240, offset:off);
      if (strlen(data) == 0) break;

      # The plugins section starts with "plugins_list":  We can find the end
      # by looking for the closing ']' character
      if ('"plugins_list":' >< data && !pluginpref_start)
      {
        chunk = strstr(data, '"plugins_list":');
        pluginpref_start = TRUE;

        # Check to see if we got the entire section in one read
        if (']' >< chunk)
        {
          pluginpref_end = TRUE;
          chunk = chunk - strstr(chunk, ']');
        }
        chromeplugins = chunk;

        # If we got the entire section in one read, we can stop reading
        # Otherwise read in the next 10240 bytes, and continue the loop
        if (pluginpref_start && pluginpref_end) break;
        else
        {
          off += 10240;
          continue;
        }
      }

      # If we found the start of the plugins section, read until we find
      # the end of the plugins section
      if (']' >< data && pluginpref_start && !pluginpref_end)
      {
        if (']' >< data)
        {
          pluginpref_end = TRUE;
          chunk = data - strstr(data, ']');
          chromeplugins = chromeplugins + chunk;
        }
        else chromeplugins = chromeplugins + data;
      }
      if (pluginpref_start && pluginpref_end) break;
      off += 10240;
    }
    CloseFile(handle:fh);
    if (chromeplugins)
    {
      chromeplugins = str_replace(string:chromeplugins, find:'\r\n', replace:'');
      chromesettings = split(chromeplugins, sep:'}', keep:FALSE);
    }
  }
  else return 'noinstall';

  # Loop over the Chrome settings and look for Java.
  # If enabled is set to False, then Java is disabled
  if (max_index(chromesettings) > 0)
  {
    for (i=0; i<max_index(chromesettings); i++)
    {
      if ('"name": "Java(TM)"' >< chromesettings[i])
      {
        if ('"enabled": true' >< chromesettings[i])
        {
          java_disabled = FALSE;
        }
        break;
      }
    }
  }
  return java_disabled;
}

function opera_check_java_disabled(path, winver)
{
  local_var java_disabled, max_java_version, max_java_path;
  local_var ini, fh, fsize, off;
  local_var data, chunk, table, flag;

  java_disabled = TRUE;
  flag = FALSE;
  max_java_path = _FCT_ANON_ARGS[0];
  if (isnull(max_java_path) || isnull(path)) return NULL;

  if (isnull(path)) return NULL;
  if (winver < 6)
    path = path + "\Application Data\Opera\Opera\operaprefs.ini";
  else
    path = path + "\Roaming\Opera\Opera\operaprefs.ini";
  ini = ereg_replace(pattern:'^[A-Za-z]:(.*)', string:path, replace:"\1");
  fh = CreateFile(
    file:ini,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  if (!isnull(fh))
  {
    fsize = GetFileSize(handle:fh);
    off = 0;

    # Read in the file
    while (off <= fsize)
    {
      data = ReadFile(handle:fh, length:10240, offset:off);
      if (strlen(data) == 0) break;

      # The section we want begins with "Disabled Plugins="
      if ('Disabled Plugins' >< data)
      {
        flag = TRUE;
        chunk = strstr(data, 'Disabled Plugins');
        table = split(chunk);
        # The first item in table should be the disabled plugins.  Check
        # if the java path is in the list.
        if (max_java_path >!< table[0]) java_disabled = FALSE;
        break;
      }
      off += 10240;
    }
    CloseFile(handle:fh);
  }
  else return 'noinstall';
  if (!flag) java_disabled = FALSE;

  return java_disabled;
}

function firefox_check_java_disabled(path, winver)
{
  local_var java_found, java_disabled;
  local_var retx, fh, fsize, off;
  local_var dirpat, paths, profile, i, dat, data, table, chunk, vals;

  java_disabled = TRUE;
  if (isnull(path)) return NULL;

  # We have to look at each profile that is set up for Firefox
  if (winver < 6)
    path = path + "\Application Data\Mozilla\Firefox\Profiles";
  else
    path = path + "\Roaming\Mozilla\Firefox\Profiles";
  path = ereg_replace(pattern:'^[A-Za-z]:(.*)', string:path, replace:"\1");

  paths = make_list();
  dirpat = path + "\*";
  retx = FindFirstFile(pattern:dirpat);
  while (!isnull(retx[1]))
  {
    profile = retx[1];
    if (profile != '.' && profile != '..')
    {
      paths = make_list(paths, tolower(path + '\\' + profile));
    }
    retx = FindNextFile(handle:retx);
  }

  if (max_index(paths) > 0)
  {
    for (i=0; i < max_index(paths); i++)
    {
      dat = paths[i] + "\pluginreg.dat";
      fh = CreateFile(
        file:dat,
        desired_access:GENERIC_READ,
        file_attributes:FILE_ATTRIBUTE_NORMAL,
        share_mode:FILE_SHARE_READ,
        create_disposition:OPEN_EXISTING
      );

      if (!isnull(fh))
      {
        java_found = FALSE;
        fsize = GetFileSize(handle:fh);
        off = 0;

        # Read in the file
        while (off <= fsize)
        {
          data = ReadFile(handle:fh, length:10240, offset:off);
          if (strlen(data) == 0) break;

          # The plugin section starts with [PLUGINS]
          if ('[PLUGINS]' >< data)
          {
            table = split(strstr(data, '[PLUGINS]'));
            if (max_index(table) > 0)
            {
              for (i=0; i < max_index(table); i++)
              {
                # Java uses npjp2.dll
                if ('npjp2.dll|$' >< table[i])
                {
                  # The third line after we find the Java plugin has the enabled/disabled flag
                  vals = split(table[i+3], sep:'|');
                  if (max_index(vals) >= 3)
                  {
                    # vals[2] should contain the enabled/disabled flag
                    # 0 and 4 are disabled.  1 and 5 are enabled
                    if (int(vals[2]) == 1 || int(vals[2]) == 5)
                      java_disabled = FALSE;
                  }
                  java_found = TRUE;
                  break;
                }
              }
            }
          }
          if (java_found) break;
          off += 10240;
        }
        CloseFile(handle:fh);
      }
    }
  }
  else return 'noinstall';
  return java_disabled;
}

winver = get_kb_item_or_exit("SMB/WindowsVersion");
info = '';
errors = make_list();

name   = kb_smb_name();
port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

res = check_java_universally_disabled(handle:hklm);
if (res)
{
  set_kb_item(name:"SMB/Java/JRE/universally_enabled", value:FALSE);
  RegCloseKey(handle:hklm);
  close_registry();
  exit(0, 'Java has been universally disabled.');
}
else set_kb_item(name:"SMB/Java/JRE/universally_enabled", value:TRUE);

# Determine the path of the highest JRE version
# This is required for properly determining the status
# in Opera
max_java_version = make_list(0, 0, 0);
java_path = '';
# Determine the max JRE version
jre_installs = get_kb_list("SMB/Java/JRE/*");
foreach jre_install (keys(jre_installs))
{
  if ('Installed' >< jre_install) continue;
  jre_version = jre_install - 'SMB/Java/JRE/';
  jre_version = ereg_replace(pattern:'^([0-9\\.]+)_.*', string:jre_version, replace:"\1");
  jre_vers = split(jre_version, sep:'.');
  # In some cases, the java version only contains two values
  if (max_index(jre_vers) == 2)
    jre_vers = make_list(jre_vers, 0);

  # Compare the java version to the max_java_version
  # If the java version is larger, set max_java_version to that value
  if (max_index(jre_vers) > 0)
  {
    for (i=0; i<max_index(jre_vers); i++)
      jre_vers[i] = int(jre_vers[i]);
      max_java_version[i] = int(max_java_version[i]);
  }

  if (
    jre_vers[0] > max_java_version[0] ||
    (
      jre_vers[0] == max_java_version[0] &&
      jre_vers[1] > max_java_version[1]
    ) ||
    (
      jre_vers[0] == max_java_version[0] &&
      jre_vers[1] == max_java_version[1] &&
      jre_vers[2] > max_java_version[2]
    )
  )
  {
    max_java_version = jre_vers;
    java_path = jre_installs[jre_install];
  }
}

if (!java_path) exit(1, 'Failed to determine the Java path.');

# Find the user directories
key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\ProfilesDirectory";
pdir = get_registry_value(handle:hklm, item:key);

if (!isnull(pdir))
{
  if (stridx(tolower(pdir), "%systemdrive%") == 0)
  {
    key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot";
    systemroot = get_registry_value(handle:hklm, item:key);
    if (isnull(systemroot)) exit(1, "Failed to get the system root on the remote host.");
    systemroot = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1:", string:systemroot);
    pdir = systemroot + substr(pdir, strlen("%systemdrive%"));
  }
}
else
{
  RegCloseKey(handle:hklm);
  close_registry();
  exit(1, 'Failed to determine the users directories.');
}

# Check if Java is enabled in Internet Explorer
info = '';
res = ie_check_java_disabled(hklm);
if (isnull(res)) errors = make_list(errors, 'Failed to check for Java status in Internet Explorer.');
if (res)
{
  info +=
    '\nJava is enabled for the following ActiveX controls and SIDs :' +
    '\n' + res +
    '\nNote that this check may be incomplete as Nessus can only check the' +
    '\nSIDs of logged on users.\n' +
    '\n';
  set_kb_item(name:"SMB/Java/JRE/ie_enabled", value:res);
}
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

share = hotfix_path2share(path:pdir);
dirpat = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\*", string:pdir);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  close_registry();
  audit(AUDIT_SHARE_FAIL, share);
}

paths = make_array();
# Loop over user directories
retx = FindFirstFile(pattern:dirpat);
while (!isnull(retx[1]))
{
  path = NULL;
  user = retx[1];
  if (user != '.' && user != '..')
  {
    # 2k / 2k3 / XP
    if (winver < 6)
      path = pdir + '\\' + user;
    else path = pdir + '\\' + user + "\AppData";

    if (!isnull(path))
    {
      lcpath = tolower(path);
      if (!paths[user]) paths[user] = path;
    }
  }
  retx = FindNextFile(handle:retx);
}

# Loop over the user directories and read the
# configuration files for the browsers.  The plugin only
# loads for Java version > 1.5
java_enabled = make_array('chrome', '', 'opera', '', 'firefox', '');
info2 = '';
if (max_java_version[0] > 1 ||
    max_java_version[0] == 1 && max_java_version[1] > 5)
{
  if (max_index(keys(paths)))
  {
    foreach user (keys(paths))
    {
      browsers = '';
      strip_path = dirpat - "\*";
      if (reparse_points_exist_in_path(check_path:strip_path))
        continue;
      # Check Google Chrome
      res = chrome_check_java_disabled(path:paths[user], winver:winver);
      if (isnull(res)) errors = make_list(errors, 'Failed to check Java status in Google Chrome.');
      if (!res && 'noinstall' >!< res)
        java_enabled['chrome'] = java_enabled['chrome'] + user + ',';


      # Check Opera
      res = opera_check_java_disabled(path:paths[user], winver:winver, java_path);
      if (isnull(res)) errors = make_list(errors, 'Failed to check Java status in Opera.');
      if (!res && 'noinstall' >!< res)
        java_enabled['opera'] = java_enabled['opera'] + user + ',';

      # Check Firefox
      res = firefox_check_java_disabled(path:paths[user], winver:winver);
      if (isnull(res)) errors = make_list(errors, 'Failed to check Java status in Firefox.');
      if (!res && 'noinstall' >!< res)
        java_enabled['firefox'] = java_enabled['firefox'] + user + ',';
    }
  }
}
NetUseDel();

if (java_enabled['chrome']) set_kb_item(name:"SMB/Java/JRE/chrome_enabled", value:java_enabled['chrome']);
if (java_enabled['opera']) set_kb_item(name:"SMB/Java/JRE/opera_enabled", value:java_enabled['opera']);
if (java_enabled['firefox']) set_kb_item(name:"SMB/Java/JRE/firefox_enabled", value:java_enabled['firefox']);

if (info)
{
  if (report_verbosity > 0)
  {
    if (max_index(errors))
    {
      info +=
        '\n' +
        'Note that the results may be incomplete because of the following ';

      if (max_index(errors) == 1) info += 'error\nthat was';
      else info += 'errors\nthat were';

      info +=
        ' encountered :\n' +
        '\n' +
        '  ' + join(errors, sep:'\n  ') + '\n';
    }
    security_note(port:port, extra:info);
  }
  else
  {
    security_note(port);
    if (max_index(errors)) exit(1, 'The result may be incomplete because of one or more errors verifying installs.');
  }
  exit(0);
}
else
{
  if (max_index(errors))
  {
    if (max_index(errors) == 1) errmsg = errors[0];
    else errmsg = 'Errors were encountered verifying installs :\n  ' + join(errors, sep:'\n  ');

    exit(1, errmsg);
  }
  else
  {
    extra =
      'Java has been disabled for all detected users and ActiveX controls.\n' +
      'Note that the check may not be complete, as Nessus can only check the\n' +
      'SIDs of logged on users.\n';
    exit(0, extra);
  }
}
