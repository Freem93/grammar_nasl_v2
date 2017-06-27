#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63418);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/10 22:03:56 $");

  script_name(english:"Microsoft System Center Operations Manager Component Installed");
  script_summary(english:"Checks registry and FS for SCOM");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A data center management system component is installed on the remote
Windows host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Microsoft System Center Operations Manager (SCOM, formerly known as
Microsoft Operations Manager) is a data center management system.  A
component of the SCOM system is installed on the remote host."
  );
   # http://www.microsoft.com/en-us/server-cloud/system-center/datacenter-management.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f456195f");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:system_center_operations_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

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

appname = 'System Center Operations Manager';

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Microsoft\Microsoft Operations Manager";
subkeys = get_registry_subkeys(handle:hklm, key:key);
paths = make_array(); # key = path, value = product name

foreach subkey (subkeys)
{
  if (subkey =~ '^[0-9\\.]+$')
  {
    subkey = key + "\" + subkey + "\Setup";
    names = make_list('InstallDirectory', 'Product');
    values = get_values_from_key(handle:hklm, key:subkey, entries:names);
    path = values['InstallDirectory'];

    if (!isnull(path))
    {
      product = values['Product'];
      if (isnull(product))
        product = 'n/a';

      paths[path] = product;
    }
  }
}

RegCloseKey(handle:hklm);

if (max_index(keys(paths)) == 0)
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
close_registry(close:FALSE);

installs = make_array(); # key = path, value = product name

foreach path (keys(paths))
{
  exe = path + "\HealthService.exe";
  if (hotfix_file_exists(path:exe))
  {
    product = paths[path];
    installs[path] = product;
  }
}

hotfix_check_fversion_end();

if (max_index(keys(installs)) == 0)
  audit(AUDIT_UNINST, appname);

set_kb_item(name:'SMB/System Center Operations Manager/Installed', value:TRUE);

port = kb_smb_transport();

report = '';
foreach path (keys(installs))
{
  product = installs[path];
  set_kb_item(name:'SMB/System Center Operations Manager/Install/' + product, value:path);

  register_install(
    app_name:product,
    path:path,
    cpe:"cpe:/a:microsoft:system_center_operations_manager");

  report +=
    '\n  Path    : ' + path +
    '\n  Product : ' + installs[path] + '\n';
}

if (report_verbosity > 0)
  security_note(port:port, extra:report);
else
  security_note(port);
