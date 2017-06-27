#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64378);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/12 02:12:32 $");

  script_name(english:"IBM Informix Genero Detection");
  script_summary(english:"Checks for installs of IBM Informix Genero");

  script_set_attribute(attribute:"synopsis", value:"The remote host has an application development environment.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has IBM Informix Genero, an application development
environment that provides graphical tools for developing business
applications."
  );
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/software/data/informix/tools/genero.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:informix");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:ibm:informix_genero");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

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
appname = 'IBM Informix Genero';
kb_base = "SMB/IBM_Informix_Genero/";

install_num = 0;
paths = make_list();
installs = make_array();

registry_init();
handle = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

key = "SOFTWARE\IBM\Informix Genero";
subkeys = get_registry_subkeys(handle:handle, key:key);

foreach subkey (subkeys)
{
  newKey = key + "\" + subkey;
  verSubKey = get_registry_subkeys(handle:handle, key:newKey);
  foreach verkey (verSubKey)
  {
    if (verkey !~ "^[0-9.]+$")
    {
       entry = newKey + "\" + verkey + "\InstallDirectory";
       path = get_registry_value(handle:handle, item:entry);
       if (!isnull(path)) paths = make_list(paths, path);
    }
  }
}
RegCloseKey(handle:handle);
close_registry();
if(max_index(paths)==0) audit(AUDIT_NOT_INST, appname);

foreach path (paths)
{
  exe = path + "gdc\bin\gdc.exe";
  ver = hotfix_get_fversion(path:exe);
  if (ver['error'] != HCF_OK) continue;
  else
  {
    version = join(ver['value'], sep:'.');
    installs[path] = version;
    set_kb_item(name: kb_base + install_num + "/Path", value:path);
    set_kb_item(name: kb_base + install_num + "/Version", value:version);
    register_install(
      app_name:appname,
      path:path,
      version:version,
      cpe:"cpe:/a:ibm:informix");
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
