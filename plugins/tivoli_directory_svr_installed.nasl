#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58813);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/13 20:51:06 $");

  script_name(english:"IBM Security Directory Server Installed (credentialed check)");
  script_summary(english:"Checks for Security Directory Server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an identity management application
installed.");
  script_set_attribute(attribute:"description", value:
"IBM Security Directory Server, formerly known as IBM Tivoli
Directory Server, an identity management application, is
installed on the remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"http://www-03.ibm.com/software/products/en/directoryserv");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/20");

  script_set_attribute(attribute:"plugin_type", value:"local");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:security_directory_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_directory_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_func.inc");
include("smb_reg_query.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_name = "IBM Security Directory Server";

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

key   = "SOFTWARE\IBM\IDSLDAP";
subkeys = get_registry_subkeys(handle:hklm, key:key);

if (empty_or_null(subkeys))
{
  RegCloseKey(handle:hklm);
  close_registry();
  audit(AUDIT_NOT_INST, app_name);
}

errors = make_list();
paths  = make_list();
installed = FALSE;

foreach subkey (subkeys)
{
  home_key = key + "\" + subkey;
  item = get_values_from_key(handle:hklm, key:home_key, entries:make_list('LDAPHome'));
  path = item['LDAPHome'];

  if (!isnull(path))
    paths = make_list(paths, path); 
}

RegCloseKey(handle:hklm);

if (max_index(paths) < 1)
{
  close_registry();
  audit(AUDIT_NOT_INST, app_name);
}

close_registry(close:FALSE);

foreach path (paths)
{
  dll = hotfix_append_path(path:path, value:"lib\libidsldap.dll");

  version = hotfix_get_fversion(path:dll); 
  error = hotfix_handle_error(error_code:version['error'], file:dll, appname:app_name, exit_on_fail:FALSE);
  if (error)
  {
    errors = make_list(errors, error);
    continue;
  }

  version = join(version['value'], sep:'.');

  installed = TRUE;

  register_install(
    app_name:app_name,
    path:path,
    version:version,
    cpe:"cpe:/a:ibm:security_directory_server"
  );
}

close_registry();

if (installed)
  report_installs(app_name:app_name, port:kb_smb_transport());
else if ((max_index(errors)) == 1)
  exit(1, "The following error has occurred : " + errors[0] + ".");
else if ((max_index(errors)) > 1)
  exit(1, "The following errors have occurred : " + join(errors, "\n\t"));
else audit(AUDIT_UNINST, app_name);
