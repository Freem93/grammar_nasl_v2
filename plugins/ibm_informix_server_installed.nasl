#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70097);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/13 20:51:06 $");

  script_name(english:"IBM Informix Dynamic Server Detection (credentialed check)");
  script_summary(english:"Detects IBM Informix Dynamic Server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a database server installed.");
  script_set_attribute(attribute:"description", value:
"IBM Informix Dynamic, a database server, is installed on the remote
Windows host.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/software/data/informix/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:informix_dynamic_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

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

port = kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

appname = 'IBM Informix Dynamic Server';
kb_base = "SMB/IBM_Informix_Server/";

install_num = 0;
installs = make_array();

registry_init();
handle = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

key = "SOFTWARE\Informix\DBMS";
subkeys = get_registry_subkeys(handle:handle, key:key);
if (isnull(subkeys))
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}

foreach subkey (subkeys)
{
  newKey = key + "\" + subkey;
  dir_entry = newKey + "\Install_Dir";
  path = get_registry_value(handle:handle, item:dir_entry);
  ver_entry = newKey + "\Version";
  version = get_registry_value(handle:handle, item:ver_entry);
  if (!isnull(path) && !isnull(version)) installs[path] = version;
}

RegCloseKey(handle:handle);

if (max_index(keys(installs)) == 0)
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}

close_registry(close:FALSE);
# verified software is actually installed
# get version from esql.exe client
foreach path (keys(installs))
{
  exe = path + "\bin\esql.exe";
  res = hotfix_get_fversion(path:exe);
  if (res['error'] == HCF_OK)
  {
    version = installs[path];
    set_kb_item(name: kb_base + install_num + "/Path", value:path);
    set_kb_item(name: kb_base + install_num + "/Version", value:version);
    # store the exe value in the extras?
    register_install(
      app_name:appname,
      path:path,
      version:version,
      cpe:"cpe:/a:ibm:informix_dynamic_server");
    install_num++;
    continue;
  }

  dll = path + "\bin\infxsnmp.dll";
  res = hotfix_get_fversion(path:dll);
  if (res['error'] == HCF_OK)
  {
    version = installs[path];
    set_kb_item(name: kb_base + install_num + "/Path", value:path);
    set_kb_item(name: kb_base + install_num + "/Version", value:version);
    # store the dll value in the extras?
    register_install(
      app_name:appname,
      path:path,
      version:version,
      cpe:"cpe:/a:ibm:informix_dynamic_server");
    install_num++;
  }
}
hotfix_check_fversion_end();

if (install_num == 0) audit(AUDIT_UNINST, appname);

set_kb_item(name:kb_base + 'NumInstalled', value:install_num);
set_kb_item(name:kb_base + 'Installed', value:install_num);

if (report_verbosity > 0)
{
  report = '';
  foreach path (keys(installs))
  {
    report +=
      '\n  Path    : ' + path    +
      '\n  Version : ' + installs[path] + '\n';
  }
  security_note(port:port, extra:report);
}
else security_note(port);
