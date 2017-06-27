#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(65810);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/08 22:04:50 $");

  script_name(english:"QlikView Installed");
  script_summary(english:"Checks for QlikView install");

  script_set_attribute(attribute:"synopsis", value:"A business delivery platform is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"QlikView, a business delivery platform, is installed on the remote
host.");
  script_set_attribute(attribute:"see_also", value:"http://www.qlikview.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qlik:qlikview");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

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

path = NULL;
key = NULL;
kb_base = "SMB/qlikview/";
appname = "QlikView";

list = get_kb_list_or_exit("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
foreach name (keys(list))
{
  prod = list[name];
  if ("QlikView" >< prod)
  {
    key = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
    key = str_replace(find:"/", replace:"\", string:key);
    break;
  }
}
if (!isnull(key))
{
  registry_init();
  handle = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  values = get_values_from_key(handle:handle, key:key, entries:make_list('InstallLocation'));
  if (!isnull(values)) path = values['InstallLocation'];
  RegCloseKey(handle:handle);
}

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
close_registry(close:FALSE);

filePath = path + "\Qv.exe";

ver = hotfix_get_fversion(path:filePath);
hotfix_check_fversion_end();
if (ver['error'] == HCF_NOENT) audit(AUDIT_UNINST, appname);
else if (ver['error'] != HCF_OK) audit(AUDIT_VER_FAIL, filePath);

version = join(ver['value'],sep:'.');
set_kb_item(name:kb_base + "Installed", value:TRUE);
set_kb_item(name:kb_base + "Path", value:path);
set_kb_item(name:kb_base + "Version", value:version);

register_install(
  app_name:appname,
  path:path,
  version:version,
  cpe:"cpe:/a:qlik:qlikview");

report = "";
port = kb_smb_transport();
if (report_verbosity > 0)
{
  report +=
      '\n  Path    : ' + path +
      '\n  Version : ' + version + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
