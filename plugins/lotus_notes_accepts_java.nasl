#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66637);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/16 14:02:52 $");

  script_cve_id("CVE-2013-0127", "CVE-2013-0538");
  script_bugtraq_id(59589, 59590);
  script_osvdb_id(92899, 92900);
  script_xref(name:"CERT", value:"912420");

  script_name(english:"IBM Notes Accepts JavaScript Tags Inside HTML Emails");
  script_summary(english:"Checks variables in notes.ini file");

  script_set_attribute(attribute:"synopsis", value:
"The version of IBM Notes installed on the remote Windows host accepts
Java applet tags and JavaScript tags inside HTML emails.");
  script_set_attribute(attribute:"description", value:
"The IBM Notes application installed on the remote Windows host accepts
Java applet tags and JavaScript tags inside HTML emails, making it
possible to load Java applets and scripts from a remote location.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2013/Apr/262");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_ibm_notes_accepts_java_applet_and_javascript_tags_inside_html_emails_cve_2013_0127_cve_2013_05381?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a0c5c8e2");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21633819");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Notes 8.5.3 Fix Pack 4 / 9.0 Interim Fix 1 or apply the
workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_notes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "lotus_notes_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/Lotus_Notes/Installed");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");

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
appname = 'IBM Lotus Notes';
kb_base = 'SMB/Lotus_Notes';

version = get_kb_item_or_exit(kb_base + '/Version');
ver_ui = get_kb_item_or_exit(kb_base + '/Version_UI');
apppath = get_kb_item_or_exit(kb_base + '/Path');

# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:apppath);
share = hotfix_path2share(path:path);

# In case we need it later, get the user directories
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\ProfilesDirectory";
pdir = get_registry_value(handle:hklm, item:key);
if (!isnull(pdir))
{
  if (stridx(tolower(pdir), "%systemdrive%") == 0)
  {
    key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot";
    systemroot = get_registry_value(handle:hklm, item:key);
    if (isnull(systemroot)) exit(1, 'Failed to get the system root on the remote host.');
    systemroot = ereg_replace(pattern:'^([A-Za-z]:).*', replace:"\1", string:systemroot);
    pdir = systemroot + substr(pdir, strlen("%systemdrive%"));
  }
}
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}


vuln = FALSE;
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i < max_index(ver); i++)
  ver[i] = int(ver[i]);

fix = '';
# Only check for a patched version if the installed
# version is either 8.x or 9.x.
if (version =~ '^8\\.0\\.[0-2][^0-9]')
{
  vuln = TRUE;
  fix = '8.5.34.13086';
}
if (version =~ '^8\\.5\\.' && ver_compare(ver:version, fix:'8.5.34.13086') < 0)
{
  vuln = TRUE;
  fix = '8.5.34.13086';
}
else if (ver[0] == 9)
{
  exe = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\nsd.exe", string:apppath);
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
    audit(AUDIT_VER_FAIL, exe);
  }
  ret = GetFileVersionEx(handle:fh);
  CloseFile(handle:fh);
  if (!isnull(ret))
  {
    timestamp = ret['dwTimeDateStamp'];
  }
  if (isnull(timestamp))
    exit(1, 'Failed to get the timestamp of ' + apppath + "\nsd.exe.");
  if (timestamp < 1367003838)
  {
    fixtimestamp = 1367003838;
    vuln = TRUE;
  }
}

# If the version is vulnerable, check for the workaround
if (vuln)
{
  ini =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\notes.ini", string:path);
  fh = CreateFile(
    file:ini,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (isnull(fh))
  {
    # If Notes is installed for multiple users, the configuration is on a per-user basis
    if (isnull(pdir))
    {
      NetUseDel();
      exit(1, 'Failed to get the user directories.');
    }
    share2 = hotfix_path2share(path:pdir);
    if (share2 != share)
    {
      NetUseDel(close:FALSE);
      share = hotfix_path2share(path:pdir);
    }
    dirpat = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\*", string:pdir);

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
      if ((retx[2] && FILE_ATTRIBUTE_DIRECTORY) && user != '.' && user != '..')
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

    if (max_index(keys(paths)))
    {
      foreach user (keys(paths))
      {
        info = '';
        strip_path = dirpath - "\*";
        if (reparse_points_exist_in_path(check_path:strip_path))
          continue;
        path = paths[user];

        if (winver < 6)
          path = path + "\Local Settings\Application Data\Lotus\Notes\Data";
        else
          path = path + "\Local\Lotus\Notes\Data";
        ini = ereg_replace(pattern:'^[A-Za-z]:(.*)', string:path, replace:"\1\notes.ini");

        fh = CreateFile(
          file:ini,
          desired_access:GENERIC_READ,
          file_attributes:FILE_ATTRIBUTE_NORMAL,
          share_mode:FILE_SHARE_READ,
          create_disposition:OPEN_EXISTING
        );
        if (!isnull(fh))
        {
          data = '';
          settings = make_list();
          fsize = GetFileSize(handle:fh);
          off = 0;
          while (off <= fsize)
          {
            data = ReadFile(handle:fh, length:10240, offset:off);
            if (strlen(data) == 0) break;
            settings = make_list(settings, split(data, keep:FALSE));

            off += 10240;
          }
          CloseFile(handle:fh);

         foundconfigs = make_array('EnableJavaApplets', FALSE, 'EnableJavaScript', FALSE, 'EnableLiveConnect', FALSE);
         found = 0;
         # Loop over the settings and check if JavaScript has been disabled
         for (i=0; i < max_index(settings); i++)
         {
           if ('EnableJavaApplets=' >< settings[i])
           {
             found++;
             foundconfigs['EnableJavaApplets'] = TRUE;
             setting = split(settings[i], sep:'=', keep:FALSE);
               if (setting[1])
                 info += '\n    - EnableJavaApplets';
           }
           else if ('EnableJavaScript=' >< settings[i])
           {
             found++;
             foundconfigs['EnableJavaScript'] = TRUE;
             setting = split(settings[i], sep:'=', keep:FALSE);
             if (setting[1])
               info += '\n    - EnableJavaScript';
           }
           else if ('EnableLiveConnect=' >< settings[i])
           {
             found++;
             foundconfigs['EnableLiveConnect'] = TRUE;
             setting = split(settings[i], sep:'=', keep:FALSE);
             if (setting[1])
               info += '\n    - EnableLiveConnect';
           }
           if (found == 3) break;
         }

         # If any of the settings weren't found in notes.ini, assume
         # they are enabled
         foreach key (keys(foundconfigs))
         {
           if (!foundconfigs[key])
             info += '\n  - ' + key;
         }
         if (info)
         {
           report +=
             '\n  ' + user + info;
         }
        }
      }
    }
    NetUseDel();
    if (report)
    {
      if (report_verbosity > 0)
      {
        extra =
          '\n  Path              : ' + apppath +
          '\n  Installed version : ' + version;
        if (fixtimestamp)
        {
          extra +=
            '\n  File              : ' + apppath + "\nsd.exe" +
            '\n  File Timestamp    : ' + timestamp +
            '\n  Fixed Timestamp   : ' + fixtimestamp + '\n';
        }
        else
          extra += '\n  Fixed version     : ' + fix + '\n';
        report =
          extra +
          '\n  Further, the following configuration settings are enabled for the' +
          '\n  listed users :' +
          '\n' +
          report + '\n';
        security_warning(port:port, extra:report);
      }
      else security_warning(port);
      exit(0);
    }
    else exit(0, 'The host is not affected because the workaround is in place.');
  }
  else
  {
    data = '';
    settings = make_list();
    fsize = GetFileSize(handle:fh);
    off = 0;
    while (off <= fsize)
    {
      data = ReadFile(handle:fh, length:10240, offset:off);
      if (strlen(data) == 0) break;
      settings = make_list(settings, split(data, keep:FALSE));

      off += 10240;
    }
    CloseFile(handle:fh);
    NetUseDel();

    foundconfigs = make_array('EnableJavaApplets', FALSE, 'EnableJavaScript', FALSE, 'EnableLiveConnect', FALSE);
    found = 0;
    # Loop over the settings and check if JavaScript has been disabled
    for (i=0; i < max_index(settings); i++)
    {
      if ('EnableJavaApplets=' >< settings[i])
      {
        found++;
        foundconfigs['EnableJavaApplets'] = TRUE;
        setting = split(settings[i], sep:'=', keep:FALSE);
        if (setting[1])
          info += '\n  - EnableJavaApplets';
      }
      else if ('EnableJavaScript=' >< settings[i])
      {
        found++;
        foundconfigs['EnableJavaScript'] = TRUE;
        setting = split(settings[i], sep:'=', keep:FALSE);
        if (setting[1])
          info += '\n  - EnableJavaScript';
      }
      else if ('EnableLiveConnect=' >< settings[i])
      {
        found++;
        foundconfigs['EnableLiveConnect'] = TRUE;
        setting = split(settings[i], sep:'=', keep:FALSE);
        if (setting[1])
          info += '\n  - EnableLiveConnect';
      }
      if (found == 3) break;
    }

    # If any of the settings weren't found in notes.ini, assume
    # they are enabled
    foreach key (keys(foundconfigs))
    {
      if (!foundconfigs[key])
         info += '\n  - ' + key;
    }
    if (info)
    {
      if (report_verbosity > 0)
      {
        report =
          '\n  Path              : ' + apppath +
          '\n  Installed version : ' + version;
        if (fixtimestamp)
        {
          report +=
            '\n  File              : ' + apppath + "\nsd.exe" +
            '\n  File Timestamp    : ' + timestamp +
            '\n  Fixed Timestamp   : ' + fixtimestamp + '\n';
        }
        else
          report += '\n  Fixed version     : ' + fix + '\n';
          report +=
            '\n  Further, the following configuration settings are enabled : ' +
            info;
        security_warning(port:port, extra:report);
      }
      else security_warning(port);
      exit(0);
    }
    else exit(0, 'The host is not affected because the workaround is in place.');
  }
}
else
{
  NetUseDel();
  audit(AUDIT_INST_PATH_NOT_VULN, appname, ver_ui, apppath);
}
