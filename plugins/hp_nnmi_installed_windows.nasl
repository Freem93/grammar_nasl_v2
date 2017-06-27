#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70145);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/12/08 16:16:56 $");

  script_name(english:"HP Network Node Manager i (NNMi) Detection (credentialed check)");
  script_summary(english:"Detects installs of HP Network Node Manager i (NNMi).");

  script_set_attribute(attribute:"synopsis", value:"The remote host has network management software installed.");
  script_set_attribute(attribute:"description", value:
"The remote host has HP Network Node Manager i (NNMi) installed. NNMi
is a component of HP Automated Network Management Suite.");
  # http://www8.hp.com/us/en/software-solutions/software.html?compURI=1170657
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5003fcc1");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:network_node_manager_i");
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

# {install_path : "...", data_path : "..."} from info in registry.
# Requires that registry connection already be initialized.
function get_nnmi_paths()
{
  local_var hklm;
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

  local_var env_key;
  env_key = "SYSTEM\CurrentControlSet\Control\Session Manager\Environment";

  local_var data_dir_item;
  data_dir_item = env_key + "\NnmDataDir";

  local_var install_dir_item;
  install_dir_item = env_key + "\NnmInstallDir";

  local_var items, vars;
  items = make_list(data_dir_item, install_dir_item);
  vars = get_registry_values(handle:hklm, items:items);

  RegCloseKey(handle:hklm);

  if (isnull(vars) || max_index(keys(vars)) < max_index(keys(items)))
    return NULL;

  return make_array(
    "data_path", vars[data_dir_item],
    "install_path", vars[install_dir_item]
  );
}

# Accepts NNMVersionInfo file and returns latest installation/patch.
function extract_ver()
{
  local_var ver_file;
  ver_file = _FCT_ANON_ARGS[0];

  local_var line;
  foreach line (split(ver_file, sep:'\n'))
  {
    # e.g.  NNMVersion=9.20,9.22.002,9.23.003
    # Most recent version is at the end
    local_var m;
    m = eregmatch(
      pattern : "^NNMVersion=(?:\d+\.\d+(?:\.\d+)?,)*?(\d+\.\d+(?:\.\d+)?)$",
      string  : line
    );

    if (!isnull(m))
      return m[1];
  }

  return NULL;
}

get_kb_item_or_exit("SMB/Registry/Enumerated");

app = "HP Network Node Manager i";

registry_init();

paths = get_nnmi_paths();

if (isnull(paths))
{
  hotfix_check_fversion_end();
  audit(AUDIT_NOT_INST, app);
}

install_path = paths["install_path"];
data_path = paths["data_path"];

file_retrieval = hotfix_get_file_contents(data_path + "NNMVersionInfo");

# We are done accessing file shares and registry.
hotfix_check_fversion_end();

# Check our attempt to retrieve NNMVersionInfo.
if (file_retrieval["error"] != HCF_OK)
  audit(AUDIT_NOT_INST, app);

version = extract_ver(file_retrieval["data"]);

register_install(
  app_name:app,
  path:install_path,
  version:version,
  cpe:"cpe:/a:hp:network_node_manager_i"
);
report_installs(app_name:app);
