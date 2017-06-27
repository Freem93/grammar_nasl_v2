#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59453);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/01/15 15:56:38 $");

  script_name(english:"Microsoft Dynamics AX Installed");
  script_summary(english:"Checks for DAX installation");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An enterprise resource planning (ERP) solution is installed on the
remote Windows host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Microsoft Dynamics AX, an ERP solution, is installed on the remote
host."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/en-us/dynamics/erp-ax-overview.aspx");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:dynamics_ax");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/ARCH");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("audit.inc");

arch = get_kb_item_or_exit('SMB/ARCH');

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# pretty sure this can only be installed on 64 bit OSes but just to be on the safe side...
dax_key = "SOFTWARE\Microsoft\Dynamics\";

installs = make_array();
installed_components = make_array();
subkeys = get_registry_subkeys(handle:hklm, key:dax_key);
if (!max_index(subkeys) && arch == 'x64')
{
  dax_key = "SOFTWARE\Wow6432Node\Microsoft\Dynamics\";
  subkeys = get_registry_subkeys(handle:hklm, key:dax_key);
}

foreach version (subkeys)
{
  if (version !~ '^[0-9.]+$') continue;

  path = get_registry_value(handle:hklm, item:dax_key + version + "\Setup\InstallDir");
  if (isnull(path))
  {
    path = get_registry_value(handle:hklm, item:dax_key + version + "\Setup\Application\");
    if (path) path -= "\Application";
  }
  if (!isnull(path))
  {
    installs[version] = path;
    components_key = "SOFTWARE\Microsoft\Dynamics\" + version + "\Setup\Components\";
    component_subkeys = get_registry_subkeys(handle:hklm, key:components_key);

    # keep track of what (if any) components are installed for each version of DAX
    foreach component (component_subkeys)
    {
      status = get_registry_value(handle:hklm, item:components_key + component + "\");
      if (status == 'Installed')
      {
        if (isnull(installed_components[version]))
          installed_components[version] = make_list(component);
        else
          installed_components[version] = make_list(installed_components[version], component);
      }
    }
  }
}

RegCloseKey(handle:hklm);

if (max_index(keys(installs)) == 0)
{
  close_registry();
  audit(AUDIT_NOT_INST, 'Microsoft Dynamics');
}
else
  close_registry(close:FALSE);

# it appears only one version can be installed at once, but it's possible multiple versions will show
# up in the registry due to unclean uninstalls. the plugin will stop on the first verified install
installed = FALSE;
foreach version (keys(installs))
{
  path = installs[version];
  if ('4.0' >< version) dll = path + "\Client\Bin\Ax32.exe";
  else
    dll = path + "\Setup\Microsoft.Dynamics.Setup.Components.dll";

  if (hotfix_file_exists(path:dll))
  {
    set_kb_item(name:'SMB/microsoft_dynamics_ax/path', value:path);
    set_kb_item(name:'SMB/microsoft_dynamics_ax/ver', value:version);  # not granular enough for most version checks (e.g. "6.0")

    foreach component (installed_components[version])
      set_kb_item(name:'SMB/microsoft_dynamics_ax/installed_component/' + component, value:TRUE);

    installed = TRUE;
    break;
  }
}

hotfix_check_fversion_end();

if (!installed)
  audit(AUDIT_UNINST, 'Microsoft Dynamics');

port = kb_smb_transport();

if (report_verbosity > 0)
{
  report =
    '\n  Path : ' + path +
    '\n  Version : ' + version + '\n';

  if (installed_components[version])
    report += '  Installed Components : ' + join(installed_components[version], sep:', ') + '\n';

  security_note(port:port, extra:report);
}
else security_note(port);
