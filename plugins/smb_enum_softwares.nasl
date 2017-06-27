#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(20811);
 script_version("$Revision: 1.15 $");
 script_cvs_date("$Date: 2013/07/25 18:18:35 $");
 
 script_name(english:"Microsoft Windows Installed Software Enumeration (credentialed check)");
 script_summary(english:"Enumerates the list of remote software");
 
 script_set_attribute(attribute:"synopsis", value:"It is possible to enumerate installed software.");
 script_set_attribute(attribute:"description", value:'
This plugin lists software potentially installed on the remote host by
crawling the registry entries in :

  HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall
  HKLM\\SOFTWARE\\Microsoft\\Updates

Note that these entries do not necessarily mean the applications are
actually installed on the remote host - they may have been left behind
by uninstallers, or the associated files may have been manually
removed.');
 script_set_attribute(attribute:"solution", value:
"Remove any applications that are not compliant with your organization's
acceptable use and security policies.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/26");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

#

include("smb_func.inc");
include("smb_reg_query.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

global_var MAX_DEPTH, MAX_INSTALLS;
MAX_INSTALLS = 4000; # unless report verbosity is "Verbose", this is the maximum number of installs/updates reported in the plugin output
MAX_DEPTH = 3;

function find_updates(hklm, key, depth)
{
  local_var subkeys, values, updates, names, desc, ver, date, installed, more_updates, update, subkey;
  if (isnull(depth))
    depth = 0;

  subkeys = get_registry_subkeys(handle:hklm, key:key);
  updates = make_array();

  foreach subkey (subkeys)
  {
    names = make_list('PackageName', 'PackageVersion', 'InstalledDate', 'Installed');
    values = get_values_from_key(handle:hklm, key:key + "\" + subkey, entries:names);
    desc = values['PackageName'];   # currently not reported in the plugin output
    ver = values['PackageVersion'];
    date = values['InstalledDate'];
    installed = values['Installed'];
    
    if (!isnull(desc) || !isnull(ver) || !isnull(date) || !isnull(installed))
    {
      # it's possible all three of these will be NULL in situations when only
      # "Installed" is present (this is a DWORD set to 0 or 1)
      updates[subkey]['desc'] = desc;
      updates[subkey]['ver'] = ver;
      updates[subkey]['date'] = date;
    }
    else if (depth < MAX_DEPTH)
    {
      more_updates = find_updates(hklm:hklm, key:key + "\" + subkey, depth:depth + 1);
      foreach update (keys(more_updates))
      {
        updates[update]['desc'] = more_updates[update]['desc'];
        updates[update]['ver'] = more_updates[update]['ver'];
        updates[update]['date'] = more_updates[update]['date'];
      }
    }
  }

  if (max_index(keys(updates)) == 0)
    updates = NULL;

  return updates;
}

port = kb_smb_transport ();

display_names = get_kb_list ("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
display_vers  = get_kb_list ("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayVersion");
install_dates  = get_kb_list ("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/InstallDate");
if (isnull(display_names) && isnull(display_vers)) exit(0);

apps = make_array();
foreach key (keys(display_names))
{
  matches = eregmatch(string:key, pattern:"^(SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/.+)/DisplayName$");
  if (isnull(matches)) continue; # based on the arg passed to get_kb_list() above, the eregmatch() call should never fail

  app_key = matches[1];
  apps[app_key]['name'] = display_names[key];
  apps[app_key]['version'] = display_vers[app_key + '/DisplayVersion'];
  apps[app_key]['installdate'] = install_dates[app_key + '/InstallDate'];
}

foreach key (keys(display_vers))
{
  matches = eregmatch(string:key, pattern:"^(SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/)(.+)/DisplayVersion$");
  if (isnull(matches)) continue; # based on the arg passed to get_kb_list() above, the eregmatch() call should never fail

  app_key = matches[1] + matches[2];
  if (apps[app_key]) continue;

  apps[app_key]['name'] = matches[2];
  apps[app_key]['version'] = display_vers[key];
  apps[app_key]['installdate'] = install_dates[app_key + '/InstallDate'];
}

foreach key (keys(install_dates))
{
  matches = eregmatch(string:key, pattern:"^(SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/)(.+)/InstallDate$");
  if (isnull(matches)) continue; # based on the arg passed to get_kb_list() above, the eregmatch() call should never fail

  app_key = matches[1] + matches[2];
  if (apps[app_key]) continue;

  apps[app_key]['name'] = matches[2];
  apps[app_key]['version'] = display_vers[app_key + '/DisplayVersion'];
  apps[app_key]['installdate'] = install_dates[app_key + '/InstallDate'];
}

# Check the HKLM\SOFTWARE\Microsoft\Updates registry hive for entries
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Microsoft\Updates";
subkeys = get_registry_subkeys(handle:hklm, key:key);

# try to recursively determine the list of installed updates. information
# on some updates may be a few levels deep in the registry
updates = make_array();
foreach app (subkeys)
{
  app_updates = find_updates(hklm:hklm, key:key + "\" + app);
  if (!isnull(app_updates))
    updates[app] = app_updates;
}
RegCloseKey(handle:hklm);
close_registry();

list = "";
unique_appvers = make_array();
installs = 0;
foreach app (sort(keys(apps)))
{
  name = apps[app]['name'];
  ver = apps[app]['version'];
  date = apps[app]['installdate'];

  # don't report the same application/version multiple times, even
  # if it is shown multiple times with different install dates
  tempver = ver;
  if (isnull(tempver)) tempver = '';
  if (unique_appvers[name][tempver])
    continue;
  else
    unique_appvers[name][tempver] = TRUE;

  list += name;
  if (!isnull(ver))
    list += '  [version ' + ver + ']';
  if (!isnull(date))
    list += '  [installed on ' + date + ']';
  list += '\n';

  if (report_verbosity < 2 && ++installs >= MAX_INSTALLS)
    break;
}

if (max_index(keys(updates)) && installs < MAX_INSTALLS)
  list += '\nThe following updates are installed :\n\n';

foreach app (sort(keys(updates)))
{
  if (++installs >= MAX_INSTALLS)
    break;

  list += app + ' :\n';

  foreach update (sort(keys(updates[app])))
  {
    list += '  ' + update;
    if (!isnull(updates[app][update]['ver']))
      list += '  [version ' + updates[app][update]['ver'] + ']';
    if (!isnull(updates[app][update]['date']))
      list += '  [installed on ' + updates[app][update]['date'] + ']';
    list += '\n';
  }
}

if(list)
{
 if (report_verbosity < 2 && installs >= MAX_INSTALLS)
 {
   report =
     '\nDue to the large number of applications installed, only a partial' +
     '\nlist of software is reported below.  To report all detected' +
     '\napplications, modify the scan policy so that the "Report Verbosity"' +
     '\nis set to "Verbose".\n';
 }
 report += string ("\n",
		"The following software are installed on the remote host :\n\n",
		list);

 security_note(extra:report, port:port);
}
