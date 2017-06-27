#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67230);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/01/13 20:51:06 $");

  script_name(english:"IBM GSKit Installed");
  script_summary(english:"Checks for IBM GSKit");

  script_set_attribute(attribute:"synopsis", value:
"A set of libraries and utilities for SSL communication is installed on
the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"IBM GSKit, a set of libraries and utilities for SSL communication, is
installed on the remote Windows host.");
  # http://www-01.ibm.com/support/knowledgecenter/SSGU8G_11.70.0/com.ibm.sec.doc/ids_ssl_006.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00d1803c");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:global_security_kit");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("install_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app = 'IBM GSKit';

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
paths = make_array();

x64 = FALSE;
kb_arch = get_kb_item("SMB/ARCH");
if (!kb_arch || "x64" >< kb_arch) x64 = TRUE;
if (x64)
  arches = make_list("", "Wow6432Node");
else
  arches = make_list("");

foreach arch (arches)
{
  key = "SOFTWARE\"+arch+"\IBM";
  subkeys = get_registry_subkeys(handle:hklm, key:key);
  foreach subkey (subkeys)
    if (subkey =~ '^GSK[0-9]+([^0-9]|$)')
    {
      path = get_registry_value(
        handle:hklm, item:key + '\\' + subkey +"\CurrentVersion\BinPath");
      if (x64 && arch != 'Wow6432Node') subkey = subkey + '_64';
      if (!isnull(path)) paths[path] = subkey;
    }
}
RegCloseKey(handle:hklm);

if (len(paths) == 0)
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}
close_registry(close:FALSE);

foreach path (keys(paths))
{
  # e.g. GSK7, GSK8_64
  gskver = tolower(paths[path]) - '_64' - 'gsk';

  bin_path = path + '\\gsk' + gskver;
  exe = NULL;

  if ('_64' >< paths[path])
    exe = bin_path + 'ver_64.exe';
  else
    exe = bin_path + 'ver.exe';

  ver = hotfix_get_fversion(path:exe);

  err_res = hotfix_handle_error(
    error_code   : ver['error'],
    file         : exe,
    appname      : app,
    exit_on_fail : FALSE
  );
  if (err_res) continue;

  version = join(ver['value'], sep:'.');
 
  register_install(
    app_name:app,
    path:path,
    version:version,
    cpe:"cpe:/a:ibm:global_security_kit"
  );
}
hotfix_check_fversion_end();

report_installs(app_name:app, port:kb_smb_transport());
