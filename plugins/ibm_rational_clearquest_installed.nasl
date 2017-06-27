#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61564);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/03/12 15:08:55 $");

  script_name(english:"IBM Rational ClearQuest Installed");
  script_summary(english:"Checks for installs of IBM Rational ClearQuest.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has change management software installed.");
  script_set_attribute(attribute:"description", value:
"IBM Rational ClearQuest, change management software for development,
is installed on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www-03.ibm.com/software/products/en/clearquest");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:rational_clearquest");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("ibm_rational_clearquest_version.inc");

appname = 'IBM Rational ClearQuest';

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Rational Software\ClearQuest";
subkeys = get_registry_subkeys(handle:hklm, key:key, wow:TRUE);

paths = make_list();

foreach item (keys(subkeys))
{
  foreach subkey (subkeys[item])
  {
    if (subkey !~ "^[0-9.]+$") continue;

    entry = key + "\" + subkey + "\Install\TARGETDIR";
    path = get_registry_value(handle:hklm, item:entry);

    if (!empty_or_null(path)) paths = make_list(paths, path);
  }
}

RegCloseKey(handle:hklm);

if (max_index(paths) == 0)
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
else
  close_registry(close:FALSE);

errors = make_list();
installed = FALSE;

foreach path (list_uniq(paths))
{
  extras = make_array();

  components = make_array(
    "Web Client",         "\cqweb\bin\cqrpc.exe",
    "Client for Windows", "\clearquest.exe",
    "Client",             "\rcp\clearquest.exe",
    "Mail Service",       "\mailservice.exe",
    "Maintenance Tool",   "\cqdbsetup.exe"
  );

  foreach component (keys(components))
  {
    file = path + components[component];
    ver = hotfix_get_fversion(path:file);
    
    error = hotfix_handle_error(error_code:ver['error'], file:file, exit_on_fail:FALSE);
   
    # Client component has no file version 
    if ("Failed to get the file version of" >< error)
      extras[component] = UNKNOWN_VER;  
    else if (error)
      errors = make_list(errors, error);
    else
    {
      ver_ui   = rational_clearquest_ver_to_verui(ver:ver['value']);
      extras[component] = ver_ui;
    }
  }

  # This version is used for the general version
  # this DLL is always updated between versions including interim fixes
  file = path + "\cqprodinfo.dll";
  ver = hotfix_get_fversion(path:file);
  
  error = hotfix_handle_error(
    error_code:ver['error'], file:file, exit_on_fail:FALSE); 
  if (error)
  {
    errors = make_list(errors, error);
    continue;
  }
  
  file_ver = join(ver['value'], sep:'.');
  ver_ui   = rational_clearquest_ver_to_verui(ver:ver['value']);
  
  register_install(
    app_name:appname,
    path:path,
    version:file_ver,
    display_version:ver_ui,
    cpe:"cpe:/a:ibm:rational_clearquest",
    extra_no_report:extras);

  if (!installed) installed = TRUE;
}

hotfix_check_fversion_end();

if (installed)
  report_installs(app_name:appname, port:kb_smb_transport());
else
{
  if ((max_index(errors)) == 1)
    exit(1, 'The following error has occurred :\n' + errors[0]);
  else if ((max_index(errors)) > 1)
    exit(1, 'The following errors have occurred :\n' + join(errors, sep:'\n'));
  else audit(AUDIT_NOT_INST, appname);
}
