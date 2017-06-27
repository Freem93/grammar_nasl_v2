#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58648);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/12 02:12:31 $");

  script_name(english:"Bitsmith Personal Knowbase Detection");
  script_summary(english:"Checks for Bitsmith Personal Knowbase install");

  script_set_attribute(
    attribute:"synopsis",
    value:
"There is personal knowledge base storage software installed on the
remote Windows host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Bitsmith Personal Knowbase is installed on the remote host.  Bitsmith
Personal Knowbase is personal knowledge base storage software."
  );

  script_set_attribute(attribute:"see_also", value:"http://www.bitsmithsoft.com/update.htm");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:bitsmith:personal_knowbase");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

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
appname = 'Bitsmith Personal Knowbase';

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
subkeys = get_registry_subkeys(handle:hklm, key:key);

installs = make_array();

foreach subkey (subkeys)
{
  if(subkey =~ "^Personal Knowbase")
  {
    display_icon = key + "\" + subkey + "\DisplayIcon";
    display_version = key + "\" + subkey + "\DisplayVersion";
    publisher = key + "\" + subkey + "\Publisher";

    # double check we are looking at the right software
    publisher = get_registry_value(handle:hklm, item:publisher);
    if(publisher != 'Bitsmith Software')
       continue;

    icon_path = get_registry_value(handle:hklm, item:display_icon);
    if (isnull(icon_path))
      exit(1, "Unable to obtain value for key : " + display_icon + '\n');

    # C:\Program Files\Knowbase1\Knowbase.exe,0
    item = eregmatch(pattern: "^([A-Za-z]:\\.+)\\Knowbase.exe,0", string: icon_path);
    if(isnull(item))
      exit(1, "Unable to extract path from DisplayIcon registry entry.");
    path = item[1];

    ver_ui = get_registry_value(handle:hklm, item:display_version);
    if (isnull(ver_ui))
      exit(1, "Unable to obtain value for key : " + display_version + '\n');

    installs[path] = make_array('ver_ui', ver_ui);
  }
}

RegCloseKey(handle:hklm);

if(max_index(installs) == 0)
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
else
  close_registry(close:FALSE);

validated_install = FALSE;

foreach path (keys(installs))
{
  exe = path + "\Knowbase.exe";
  ver = hotfix_get_fversion(path:exe);
  if (!isnull(ver['value']))
  {
    validated_install = TRUE;
    str_ver = join(sep: '.', ver['value']);
    installs[path]['ver'] = str_ver;
  }
  else installs[path]['ver'] = NULL;
}

hotfix_check_fversion_end();

if(!validated_install)
  audit(AUDIT_UNINST, appname);

kb_base = "SMB/Bitsmith_Knowbase/";

set_kb_item(name:kb_base + "Installed", value: TRUE);
install_num = 0;

report = '';
foreach path (keys(installs))
{
  if(installs[path]['ver'] == NULL)
    continue;

  set_kb_item(name:kb_base + install_num + '/Path', value: path);
  set_kb_item(name:kb_base + install_num + '/Version', value: installs[path]['ver']);
  set_kb_item(name:kb_base + install_num + '/Version_UI', value: installs[path]['ver_ui']);
  register_install(
    app_name:appname,
    path:path,
    version:installs[path]['ver'],
    display_version:installs[path]['ver_ui'],
    cpe:"x-cpe:/a:bitsmith:personal_knowbase");

  install_num ++;

  report +=
    '\n Path    : ' + path +
    '\n Version : ' + installs[path]['ver_ui'] + ' (' + installs[path]['ver'] + ')\n';
}

set_kb_item(name:kb_base + 'NumInstalls', value: install_num);

if (report_verbosity > 0) security_note(port:port, extra:report);
else security_note(port);
