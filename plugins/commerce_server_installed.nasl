#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58650);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/11 13:46:37 $");

  script_name(english:"Microsoft Commerce Server Installed");
  script_summary(english:"Checks registry/filesystem for Commerce Server");

  script_set_attribute(attribute:"synopsis", value:"An e-commerce platform is installed on the remote Windows host.");
  script_set_attribute(
    attribute:"description",
    value:
"Microsoft Commerce Server, an e-commerce platform running on .NET, is
installed on the remote host."
  );
  script_set_attribute(attribute:"see_also", value:"https://msdn.microsoft.com/en-us/library/dd452365.aspx");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Microsoft_Commerce_Server");
  script_set_attribute(attribute:"see_also", value:"http://www.sitecore.net/products/commerce-tools/sitecore-commerce");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:commerce_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/ARCH");
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
arch = get_kb_item_or_exit('SMB/ARCH');
appname = 'Commerce Server';

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
install_keys = make_list();
products = make_array();

if (arch == 'x64')
  ms_key = "SOFTWARE\Wow6432Node\Microsoft";
else
  ms_key = "SOFTWARE\Microsoft";

# 2009 and earlier
foreach subkey (get_registry_subkeys(handle:hklm, key:ms_key))
{
  if (subkey =~ "^Commerce Server [0-9]+$")
    install_keys = make_list(install_keys, ms_key + "\" + subkey);
}

# 2009 R2 & maybe later
commerce_key = ms_key + "\CommerceServer";
foreach subkey (get_registry_subkeys(handle:hklm, key:commerce_key))
{
  if (subkey =~ "^[0-9.]+$")
    install_keys = make_list(install_keys, commerce_key + "\" + subkey);
}

foreach key (install_keys)
{
  names = make_list('InstallFolder', 'ProductName');
  values = get_values_from_key(handle:hklm, key:key, entries:names);
  path = values['InstallFolder'];
  prod = values['ProductName'];
  if (isnull(path)) continue;
  if (isnull(prod)) prod = 'n/a';

  products[path] = prod;
}

# if all else fails, check the uninstall keys
if (max_index(keys(products)) == 0)
{
  names = get_kb_list_or_exit('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');
  entries = make_array();


  foreach kb_key (keys(names))
  {
    prod_name = names[kb_key];
    if (prod_name !~ '^Microsoft Commerce Server [0-9]+( .+ Edition)?$') continue;

    entry = kb_key - 'SMB/Registry/HKLM/' - 'DisplayName' + 'InstallLocation';
    entry = str_replace(string:entry, find:"/", replace:"\");
    path = get_registry_value(handle:hklm, item:entry);
    if (isnull(path)) continue;

    products[path] = prod_name;
  }
}

RegCloseKey(handle:hklm);

if (max_index(keys(products)) == 0)
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
else
{
  close_registry(close:FALSE);
}

installs = make_array();

foreach path (keys(products))
{
  dll = path + "\commerce.dll";
  if (!hotfix_file_exists(path:dll)) continue;

  # in the event that multiple commerce server installs can exist on the same host (not verified),
  # be aware that this doesn't provide a correlation between path and product name
  prod_name = products[path];
  set_kb_item(name:'SMB/commerce_server/path', value:path);
  set_kb_item(name:'SMB/commerce_server/productname', value:prod_name);

  register_install(
    app_name:appname,
    path:path,
    extra:make_array("Product Name", prod_name),
    cpe:"cpe:/a:microsoft:commerce_server");
  installs[path] = prod_name;
}

hotfix_check_fversion_end();

if (max_index(keys(installs)) == 0)
  audit(AUDIT_UNINST, appname);
else
  set_kb_item(name:'SMB/commerce_server/Installed', value:TRUE);

if (report_verbosity > 0)
{
  report = '';

  foreach path (keys(installs))
  {
    report +=
      '\n  Product : ' + installs[path] +
      '\n  Path    : ' + path + '\n';
    security_note(port:port, extra:report);
  }
}
else security_note(port);
