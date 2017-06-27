#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62681);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/03 20:48:27 $");

  script_name(english:"Adobe Bridge Installed");
  script_summary(english:"Checks for Bridge.exe.");

  script_set_attribute(attribute:"synopsis", value:
"A digital management application is installed on the remote Windows
host.");
  script_set_attribute(attribute:"description", value:
"Adobe Bridge is installed on the remote Windows host. Bridge is used
to organize creative assets, and provide centralized access for
applications in the Adobe Creative Suite.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/products/bridge.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:bridge");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:bridge_cc");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("install_func.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');

paths = make_list();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Adobe\Adobe Bridge";
subkeys = get_registry_subkeys(handle:hklm, key:key);

foreach subkey (subkeys)
{
  if (subkey !~ '^CS[0-9]+$' && subkey !~ '^CC$') continue;

  path = get_registry_value(handle:hklm, item:key + "\" + subkey + "\Installer\InstallPath");
  if (!isnull(path))
    paths = make_list(paths, path);
}

RegCloseKey(handle:hklm);

if (max_index(paths) == 0)
{
  close_registry();
  audit(AUDIT_NOT_INST, 'Adobe Bridge');
}
else
{
  close_registry(close:FALSE);
}

foreach path (paths)
{
  exe = path + "\Bridge.exe";
  version = NULL;
  verui = NULL;

  ver =  hotfix_get_fversion(path:exe);
  if (ver['error'] == HCF_NOVER)
    version = 'Unknown';
  else if (ver['error'] == HCF_OK)
  {
    ver = ver['value'];
    version = join(ver, sep:'.');
  }
  else continue;

  product = hotfix_get_pname(path:exe);
  if ( product['error'] == HCF_OK)
  {
    product = product['value'];
  }
  else continue;

  set_kb_item(name:'SMB/Adobe_Bridge/'+version+'/Path', value:path);
  set_kb_item(name:'SMB/Adobe_Bridge/'+version+'/Version', value:version);
  set_kb_item(name:'SMB/Adobe_Bridge/'+version+'/Product', value:product);

  register_install(
    app_name:'Adobe Bridge',
    path:path,
    version:version,
    extra: make_array('Product', product),
    cpe:"cpe:/a:adobe:bridge");

  report +=
    '\n  Product : ' + product +
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';
}

hotfix_check_fversion_end();

if (report)
{
  port = kb_smb_transport();
  set_kb_item(name:'SMB/Adobe_Bridge/installed', value:TRUE);
  if (report_verbosity > 0)
  {
    if (installs > 1) s = 's of Adobe Bridge were found ';
    else s = ' of Adobe Bridge was found ';
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
else audit(AUDIT_UNINST, 'Adobe Bridge');

