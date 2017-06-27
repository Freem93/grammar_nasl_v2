#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57708);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/01 19:18:42 $");

  script_name(english:"IBM MQ Server and Client Detection");
  script_summary(english:"Checks for IBM MQ server or client installation.");

  script_set_attribute(attribute:"synopsis", value:
"A message queuing server or related client software is installed on
the remote host.");
  script_set_attribute(attribute:"description", value:
"IBM MQ (formerly IBM WebSphere MQ) message queuing server or related
client software is installed on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www-03.ibm.com/software/products/en/websphere-mq");
  script_set_attribute(attribute:"see_also", value:"http://www-03.ibm.com/software/products/en/ibm-mq");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_mq");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

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
include('obj.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
app_name = "IBM WebSphere MQ";

# Gets install data from a registry key and returns install as an
# array or NULL otherwise.
function get_install_from_key(key)
{
  local_var hklm, entries, values;
  local_var name, path, type, components;
  local_var exe, exe_ver, version;
  local_var install;

  # Function can accept argument anonymously.
  if (isnull(key)) key = _FCT_ANON_ARGS[0];

  registry_init();
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  entries = make_list("FilePath", "ProductType", "Name");
  values = get_values_from_key(handle:hklm, entries:entries, key:key);

  if (isnull(values))
  {
    return NULL;
  }

  name = values["Name"];
  path = values["FilePath"];
  type = values["ProductType"];

  # Look for installed components.
  key += "\Components";
  values = get_reg_name_value_table(handle:hklm, key:key);
  RegCloseKey(handle:hklm);
  close_registry(close:FALSE);

  if (!isnull(values))
  {
    local_var component;
    components = make_list();
    foreach component (sort(keys(values)))
    {
      components = make_list(components, component);
    }
  }

  # Verify that the software is actually installed by checking for the
  # executable and grab version from that.
  exe = hotfix_append_path(path:path, value:"bin\runmqckm.exe");
  exe_ver = hotfix_get_pversion(path:exe);
  hotfix_check_fversion_end();
  if (exe_ver['error'] == HCF_OK)
  {
    # Versions might have a comma separator for some reason.
    version = str_replace(string:exe_ver['value'], find:",", replace:".");

    # Create install array and return.
    install = make_array(
      'name', name,
      'path', path,
      'version', version
      );

    if (!isnull(type)) install['type'] = type;
    if (!isnull(components)) install['components'] = components;

    return install;
  }
  else return NULL;
}

path = NULL;
type = NULL;
version = NULL;
components = NULL;
installs = make_list();
install_count = 0;
data_for_register_installs = make_nested_list();

# Get primary install information from the registry.
key = "SOFTWARE\IBM\MQSeries\CurrentVersion";
install = get_install_from_key(key);
if (!isnull(install))
{
  path = install['path'];
  type = install['type'];
  version = install['version'];
  components = install['components'];

  data_for_register_installs[install_count] = install;
  installs[install_count] = install;
  install_count = 1;
}
else
{
  close_registry();
  audit(AUDIT_NOT_INST, app_name);
}

# As of 7.1, multiple installs are supported. Search the registry for those.
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\IBM\WebSphere MQ\Installation";
subkeys = get_registry_subkeys(handle:hklm, key:key);
RegCloseKey(handle:hklm);

# Gather data for multi register_install calls.
if (!isnull(subkeys))
{
  # Process each install and add it to the installs array.
  foreach subkey (subkeys)
  {
    install_key = key + "\" + subkey;
    install = get_install_from_key(install_key);
    if (!isnull(install))
    {
      # Check for dupes pulled in by the two reg queries
      # If a dupe, skip it.
      foreach check_inst (data_for_register_installs)
      {
        if (obj_cmp(install, check_inst))
          continue;

        data_for_register_installs[install_count] = install;
        installs[install_count] = install;
        install_count++;
      }
    }
  }
}

# Close handles.
hotfix_check_fversion_end();

# Exit out if there are no installs.
if (install_count < 1) audit(AUDIT_NOT_INST, app_name);

# Save the primary install data.
set_kb_item(name:"SMB/WebSphere_MQ/Installed", value:install_count);
set_kb_item(name:"SMB/WebSphere_MQ/Path", value:path);
set_kb_item(name:"SMB/WebSphere_MQ/Version", value:version);
if (!isnull(type)) set_kb_item(name:"SMB/WebSphere_MQ/Type", value:type);
if (!isnull(components)) set_kb_item(name:"SMB/WebSphere_MQ/Components", value:join(components, sep:', '));

# Store installs for install_func.inc
foreach item (data_for_register_installs)
{
  register_install(
    app_name:app_name,
    path:item['path'],
    version:item['version'],
    extra:make_array(
      "Installed", install_count,
      "Type", type,
      "Components", join(components, sep:', ')
    ),
    cpe:"cpe:/a:ibm:websphere_mq"
  );
}

# If there are multiple installs, add each one to the KB.
if (install_count > 1)
{
  index = 0;
  foreach install (installs)
  {
    set_kb_item(name:strcat("SMB/WebSphere_MQ/", index,"/Name"), value:install['name']);
    set_kb_item(name:strcat("SMB/WebSphere_MQ/", index,"/Path"), value:install['path']);
    set_kb_item(name:strcat("SMB/WebSphere_MQ/", index,"/Version"), value:install['version']);
    if (!isnull(install['type']))
      set_kb_item(name:strcat("SMB/WebSphere_MQ/", index,"/Type"), value:install['type']);
    if (!isnull(install['components']))
      set_kb_item(name:strcat("SMB/WebSphere_MQ/", index,"/Components"),
        value:join(install['components'], sep:', '));

    index++;
  }
}

# Create report for single install
if (install_count == 1)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version;

  if (!isnull(type)) report += '\n  Type    : ' + type;
  if (!isnull(components))
  {
    report += '\n\n  The following components are installed :';

    foreach component (components) report += '\n    - ' + component;
  }

  report += '\n';
}
# Create report for multiple installs.
else
{
  report =
    '\nNessus detected ' + install_count + ' installs of ' + app_name + '.\n';

  foreach install(installs)
  {
    report +=
      '\n  Name    : ' + install['name'] +
      '\n  Path    : ' + install['path'] +
      '\n  Version : ' + install['version'];

    if (!isnull(install['type'])) report += '\n  Type    : ' + install['type'];
    if (!isnull(install['components']))
    {
      report += '\n\n  ' + install['name'] + ' has the following components that are installed :';

      foreach component (install['components']) report += '\n    - ' + component;
    }
    report += '\n';
  }
}

port = kb_smb_transport();

if (report_verbosity > 0) security_note(port:port, extra:report);
else security_note(port);
