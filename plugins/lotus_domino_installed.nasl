#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55818);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/07/12 02:12:32 $");

  script_name(english:"IBM Domino Installed");
  script_summary(english:"Checks version of IBM Domino (credentialed check)");

  script_set_attribute(attribute:"synopsis", value:"The remote host has IBM Domino installed.");
  script_set_attribute(attribute:"description", value:
"IBM Domino (formerly IBM Lotus Domino), an enterprise application for
collaborative messaging, scheduling, directory services, and web
services, is installed on the remote host.");

  script_set_attribute(attribute:"see_also", value:"http://www-03.ibm.com/software/products/en/ibmdomino");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/11");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_domino");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

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

app = 'IBM Domino';
port = kb_smb_transport();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
paths = make_array();

# Get filename of main executable (e.g. nserver.exe)
key  = "SOFTWARE\Lotus\Domino\Name";
file = get_registry_value(handle:hklm, item:key);

# Get path
key  = "SOFTWARE\Lotus\Domino\Path";
path = get_registry_value(handle:hklm, item:key);

RegCloseKey(handle:hklm);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}

if (isnull(file))
{
  close_registry();
  exit(1, "Could not find name of IBM Domino's main executable.");
}

close_registry(close:FALSE);

exe = hotfix_append_path(path:path, value:file);
ver = hotfix_get_fversion(path:exe);
hotfix_handle_error(error_code:ver['error'],
                    file:exe,
                    appname:app,
                    exit_on_fail:TRUE);

version = join(ver['value'], sep:'.');

# Report our findings.
set_kb_item(name:"SMB/Domino/Installed", value:TRUE);
set_kb_item(name:"SMB/Domino/Path", value:path);
set_kb_item(name:"SMB/Domino/Version", value:version);

# Get 'jvm.dll' version
dll = hotfix_append_path(path:path, value:"jvm\bin\classic\jvm.dll");
ver = hotfix_get_fversion(path:dll);
hotfix_handle_error(error_code:ver['error'],
                    file:dll,
                    appname:app,
                    exit_on_fail:FALSE);

hotfix_check_fversion_end();
extra = make_array();
if (ver)
{
  ver_jvm = join(ver['value'], sep:'.');
  set_kb_item(name:"SMB/Domino/Java_Version", value:ver_jvm);
  extra['Java Version'] = ver_jvm;
}

register_install(
  app_name:app,
  path:path,
  version:version,
  extra:extra,
  cpe:"cpe:/a:ibm:lotus_domino");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version +
    '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
