#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62689);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/12 02:12:31 $");

  script_name(english:"Adobe Prelude Installed");
  script_summary(english:"Checks for Prelude in registry/fs");

  script_set_attribute(attribute:"synopsis", value:"A media production application is installed on the remote host.");
  script_set_attribute(
    attribute:"description",
    value:
"Adobe Prelude, used to log and tag media with metadata, is installed on
the remote Windows host."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/products/prelude.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:adobe:prelude");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

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

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
exes = make_list();

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths";
subkeys = get_registry_subkeys(handle:hklm, key:key);

foreach subkey (subkeys)
{
  if (subkey =~ '^Adobe Prelude( CS[0-9]+)?.exe$')
  {
    exe = get_registry_value(handle:hklm, item:key + "\" + subkey + "\");

    if (!isnull(exe))
      exes = make_list(exes, exe);
  }
}

RegCloseKey(handle:hklm);

if (max_index(exes) == 0)
{
  close_registry();
  audit(AUDIT_NOT_INST, 'Adobe Prelude');
}
else
{
  close_registry(close:FALSE);
}

foreach exe (exes)
{
  # In some cases, the path is saved in the registry with " characters
  exe = str_replace(string:exe, find:'"', replace:'');
  version = NULL;
  verui = NULL;

  ver =  hotfix_get_fversion(path:exe);
  if (ver['error'] == HCF_NOVER)
    version = 'Unknown';
  else if (ver['error'] == HCF_OK)
    version = join(ver['value'], sep:'.');
  else
    continue;

  path_parts = split(exe, sep:"\", keep:TRUE);
  path = '';
  for (i = 0; i < max_index(path_parts) - 1; i++)
    path += path_parts[i];

  set_kb_item(name:'SMB/Adobe_Prelude/'+version+'/Path', value:path);
  set_kb_item(name:'SMB/Adobe_Prelude/'+version+'/ExePath', value:exe);

  register_install(
    app_name:'Adobe Prelude',
    path:path,
    version:version,
    cpe:"x-cpe:/a:adobe:prelude");

  report +=
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';
}

hotfix_check_fversion_end();

if (report)
{
  port = kb_smb_transport();
  set_kb_item(name:'SMB/Adobe_Prelude/installed', value:TRUE);
  if (report_verbosity > 0)
  {
    if (installs > 1) s = 's of Adobe Prelude were found ';
    else s = ' of Adobe Prelude was found ';
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
else audit(AUDIT_UNINST, 'Adobe Prelude');
