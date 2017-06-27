#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61486);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/09/23 15:28:39 $");

  script_name(english:"IBM Notes Client Detection");
  script_summary(english:"Detects Installs of IBM Notes Client");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a business collaboration software client
installed.");
  script_set_attribute(attribute:"description", value:
"The remote host has IBM Notes installed. IBM Notes (formerly IBM Lotus
Notes) is a business collaboration software client that connects to
IBM Notes servers. This software has various capabilities including
email, calendaring, and instant messaging.");
  script_set_attribute(attribute:"see_also", value:"http://www-03.ibm.com/software/products/us/en/ibmnotes");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_notes");
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

get_kb_item_or_exit("SMB/Registry/Enumerated");

appname = 'IBM Notes';
port = kb_smb_transport();

ver_ui_exceptions = make_array(
  "6.5.10.4075", "6.5.1 DSF1",
  "6.5.20.4319", "6.5.2 FP1",
  "6.5.30.4315", "6.5.3 CPP1",
  "6.5.30.4350", "6.5.3 FP1"
);

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Lotus\Notes\Path";

path = get_registry_value(handle:hklm, item:key);

RegCloseKey(handle:hklm);

if(isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}

close_registry(close:FALSE);

exe = hotfix_append_path(path:path, value:'notes.exe');
ver = hotfix_get_fversion(path:exe);
hotfix_handle_error(error_code:ver['error'],
                    file:exe,
                    appname:appname,
                    exit_on_fail:TRUE);

version = join(ver['value'], sep:'.');
ver_ui = '';

if(!isnull(ver_ui_exceptions[version]))
{
  ver_ui = ver_ui_exceptions[version] + ' (' + version + ')';
}
else
{
  ver = ver['value'];
  ver_ui = ver[0] + "." + ver[1] + "." + string(int(ver[2]) / 10);
  fp = ver[2] % 10;
  if (fp) ver_ui = ver_ui + " FP" + fp;
  ver_ui += ' (' + version + ')';
}

kb_base = "SMB/Lotus_Notes/";

set_kb_item(name:kb_base+"Installed", value:TRUE);
set_kb_item(name:kb_base+"Version", value:version);
set_kb_item(name:kb_base+"Version_UI", value:ver_ui);
set_kb_item(name:kb_base+"Path", value:path);

# Get 'jvm.dll' version
dll = hotfix_append_path(path:path, value:"jvm\bin\classic\jvm.dll");
ver = hotfix_get_fversion(path:dll);
hotfix_handle_error(error_code:ver['error'],
                    file:dll,
                    appname:appname,
                    exit_on_fail:FALSE);

hotfix_check_fversion_end();
extra = make_array();
if (ver)
{
  ver_jvm = join(ver['value'], sep:'.');
  set_kb_item(name:kb_base+"Java_Version", value:ver_jvm);
  extra['Java Version'] = ver_jvm;
}

register_install(
  app_name:appname,
  path:path,
  version:version,
  display_version:ver_ui,
  extra:extra,
  cpe:"cpe:/a:ibm:lotus_notes"
);

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + ver_ui +
    '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
