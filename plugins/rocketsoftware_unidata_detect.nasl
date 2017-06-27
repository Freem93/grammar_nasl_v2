#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(51461);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/07/12 02:12:32 $");

  script_name(english:"Rocket Software UniData Detection");
  script_summary(english:"Checks for Rocket Software UniData");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host is running a relational database.");

  script_set_attribute(attribute:"description", value:
"The remote Windows host is running UniData, a relational database
application.");

  script_set_attribute(attribute:"see_also", value:"http://www.rocketsoftware.com/u2/products/unidata");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('audit.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('misc_func.inc');
include("install_func.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');

# Connect to the appropriate share.
name    = kb_smb_name();
port    = kb_smb_transport();
login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();

registry_init();
hive = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = 'SOFTWARE\\IBM\\UniData';
subkeys = get_registry_subkeys(handle:hive, key:key);

# Get the install path
paths = make_list();
foreach subkey (subkeys)
{
  if (subkey =~ '^[0-9\\.]+$')
  {
    entry = key + '\\' + subkey + '\\UDTHOME';
    path = get_registry_value(handle:hive, item:entry);
    if (!isnull(path)) paths = make_list(paths, path);
  }
}

# Newer versions of the software create a different registry key
key = 'SOFTWARE\\Rocket Software\\UniData';
subkeys = get_registry_subkeys(handle:hive, key:key);
foreach subkey (subkeys)
{
  if (subkey =~ '^[0-9\\.]+$')
  {
    entry = key + '\\' + subkey + '\\UDTHOME';
    path = get_registry_value(handle:hive, item:entry);
    if (!isnull(path)) paths = make_list(paths, path);
  }
}
RegCloseKey(handle:hive);

if (max_index(paths) < 1)
{
  close_registry();
  audit(AUDIT_NOT_INST, 'Rocket Software UniData');
}
close_registry(close:FALSE);

report = '';
foreach path (paths)
{
  dll = path + "\bin\unidata.dll";
  ver = hotfix_get_fversion(path:dll);

  if (isnull(ver['value']))
  {
    version = 'Unknown';
    debug_print('Couldn\'t get the version of '+path+"\bin\unidata.dll");
  }
  else
  {
    verarr = ver['value'];
    version = verarr[0] + '.' + verarr[1] + '.' + verarr[2];
    build = verarr[3];
  }
  report +=
    '\n  Path    : ' + path +
    '\n  Version : ' + version +
    '\n  Build   : ' + build + '\n';
  version += '.' + build;

  set_kb_item(name:'SMB/RocketSoftware/UniData/'+version+'/path', value:path);

  register_install(
    app_name:'Rocket Software UniData',
    path:path,
    version:version,
    extra:make_array('Build', build));
}
hotfix_check_fversion_end();

if (report)
{
  set_kb_item(name:'SMB/RocketSoftware/UniData/installed', value:TRUE);
  if (report_verbosity > 0)
  {
    if (max_index(paths) > 1) s = 's of Rocket Software UniData were found ';
    else s = ' of Rocket Software UniData was found ';
    report =
      '\n  The following install' + s + 'on the' +
      '\n  remote host :' +
      '\n' +
      report;
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else exit(0, 'No Rocket Software UniData installs were detected on the remote host.');
