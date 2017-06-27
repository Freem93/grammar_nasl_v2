#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58645);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/12 02:12:32 $");

  script_name(english:"Microsoft Visual FoxPro Installed");
  script_summary(english:"Checks registry/filesystem for VFP");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A programming language environment is installed on the remote Windows
host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Microsoft Visual FoxPro, an IDE for the Visual FoxPro programming
language, is installed on the remote Windows host."
  );
  script_set_attribute(attribute:"see_also", value:"http://msdn.microsoft.com/vfoxpro");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_foxpro");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("audit.inc");
include("install_func.inc");

port = kb_smb_transport();
appname = 'Visual FoxPro';

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Microsoft\VisualFoxPro";
subkeys = get_registry_subkeys(handle:hklm, key:key);
paths = make_array();

foreach subkey (subkeys)
{
  if (subkey !~ "^[0-9.]+$") continue;

  entry = key + "\" + subkey + "\Setup\VFP\ProductDir";
  path = get_registry_value(handle:hklm, item:entry);

  if (isnull(path)) continue;
  else paths[path] = subkey;  # key = path, value = version
}

RegCloseKey(handle:hklm);

if (max_index(keys(paths)) == 0)
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
else
  close_registry(close:FALSE);

installs = make_array();

foreach path (keys(paths))
{
  major_ver = paths[path] - '.0';
  exe = path + "\vfp" + major_ver + ".exe";
  ver = hotfix_get_fversion(path:exe);

  if (isnull(ver['value']))
    continue;
  else
    installs[path] = join(ver['value'], sep:'.');

  # e.g., SMB/VFP8.0/path
  set_kb_item(name:'SMB/VFP' + paths[path] + '/path', value:path);
  register_install(
    app_name:appname,
    path:path,
    version:installs[path],
    cpe:"cpe:/a:microsoft:visual_foxpro");
}

hotfix_check_fversion_end();

if (max_index(keys(installs)) == 0)
  audit(AUDIT_UNINST, appname);
else
  set_kb_item(name:'SMB/VFP/Installed', value:TRUE);

if (report_verbosity > 0)
{
  report = '';

  foreach path (keys(installs))
  {
    report +=
      '\n  Path    : ' + path +
      '\n  Version : ' + installs[path] + '\n';
  }

  security_note(port:port, extra:report);
}
else security_note(port);

