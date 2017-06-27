#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58847);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/08 22:04:50 $");

  script_name(english:"Intuit QuickBooks Installed");
  script_summary(english:"Checks registry/file system for QB");

  script_set_attribute(attribute:"synopsis", value:"Business accounting software is installed on the remote Windows host.");
  script_set_attribute(
    attribute:"description",
    value:
"QuickBooks, accounting software for small businesses, is installed on
the remote host."
  );
  script_set_attribute(attribute:"see_also", value:"http://quickbooks.intuit.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:intuit:quickbooks");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

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
appname = 'QuickBooks';

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Intuit\QuickBooks";
qb_subkeys = get_registry_subkeys(handle:hklm, key:key);
products = make_array();

foreach ver (qb_subkeys)
{
  if (ver !~ "^[0-9.]+$") continue;

  # different editions of QB have install information in different subkeys. e.g., for Enterprise Solutions it's "bel"
  ver_key = key + "\" + ver;
  ver_subkeys = get_registry_subkeys(handle:hklm, key:ver_key);

  foreach edition (ver_subkeys)
  {
    edition_key = ver_key + "\" + edition;
    values = get_values_from_key(handle:hklm, key:edition_key, entries:make_list('Path', 'Product'));
    path = values['Path'];
    prod = values['Product'];

    if (isnull(path)) continue;
    if (isnull(prod)) prod = 'n/a';
    products[path] = prod;
  }
}

RegCloseKey(handle:hklm);

if (max_index(keys(products)) == 0)
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
else
  close_registry(close:FALSE);

installs = make_array();

foreach path (keys(products))  # 'path' should be the absolute path to an exe
{
  if (!hotfix_file_exists(path:path)) continue;

  # extract the dir from the path
  parts = split(path, sep:"\", keep:FALSE);
  dir = '';
  for (i = 0; i < max_index(parts) - 1; i++)
    dir += parts[i] + "\";

  prod = products[path];
  installs[dir] = prod;
  set_kb_item(name:'SMB/QuickBooks/' + prod + '/path', value:dir);

  register_install(
    app_name:appname,
    path:dir,
    cpe:"cpe:/a:intuit:quickbooks");
}

hotfix_check_fversion_end();

if (max_index(keys(installs)) == 0)
  audit(AUDIT_UNINST, appname);
else
  set_kb_item(name:'SMB/QuickBooks/Installed', value:TRUE);

if (report_verbosity > 0)
{
  report = '';

  foreach path (keys(installs))
  {
    report +=
      '\n  Product : ' + installs[path] +
      '\n  Path    : ' + path + '\n';
  }

  security_note(port:port, extra:report);
}
else security_note(port);
