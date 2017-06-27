#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60021);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/12 02:12:33 $");

  script_name(english:"StudioLine Photo Basic Detection");
  script_summary(english:"Detects installs of StudioLine Photo Basic");

  script_set_attribute(attribute:"synopsis", value:"The remote host has image editing software installed.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has StudioLine Photo Basic installed.  StudioLine
Photo Basic is an image editing software."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.studioline.biz/EN/products/overview-photo-basic/default.htm");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:studioline:photobasic");
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
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");

port = kb_smb_transport();
appname = 'StudioLine Photo Basic';

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\H&M System Software\StudioLine Photo Basic";
subkeys = get_registry_subkeys(handle:hklm, key:key);
paths = make_list();

foreach subkey (subkeys)
{
  if (subkey =~ '^[0-9\\.]+$')
  {
    entry = key + '\\' + subkey + "\InstallPath\";
    entry1 = key + '\\' + subkey + "\IniFilePath\";
    path = get_registry_value(handle:hklm, item:entry);
    if(isnull(path))
      path = get_registry_value(handle:hklm, item:entry1);
    if (!isnull(path)) paths = make_list(paths, path);
  }
}

RegCloseKey(handle:hklm);

if (max_index(paths) == 0)
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
close_registry(close:FALSE);

installs = make_array();
validatedinstall = FALSE;
foreach path (paths)
{
  dll = path + "\SLVer.dll";
  ver = hotfix_get_fversion(path:dll);
  if (!isnull(ver['value']))
  {
    validatedinstall = TRUE;
    str_ver = join(sep:'.', ver['value']);
    installs[path] = str_ver;
  }
}

hotfix_check_fversion_end();

if (!validatedinstall) audit(AUDIT_UNINST, appname);

kb_base = 'SMB/StudioLine_PhotoBasic/';
set_kb_item(name:kb_base+'Installed', value:TRUE);

report = '';
foreach path (keys(installs))
{
  set_kb_item(name:kb_base+'Installs/'+installs[path], value:path);

  register_install(
    app_name:appname,
    path:path,
    version:installs[path],
    cpe:"x-cpe:/a:studioline:photobasic");

  report +=
    '\n  Path    : ' + path +
    '\n  Version : ' + installs[path] + '\n';
}

if (report_verbosity > 0) security_note(port:port, extra:report);
else security_note(port);
