#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69304);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/07/29 20:42:34 $");

  script_name(english:"Oracle JRockit Detection");
  script_summary(english:"Detects installs of Oracle JRockit.");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host contains a Java programming platform.");
  script_set_attribute(attribute:"description", value:
"The remote host has Oracle JRockit installed. JRockit is an alternate
Java Virtual Machine.");

  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/middleware/jrockit/overview/index.html");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jrockit");
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

get_kb_item_or_exit("SMB/Registry/Enumerated");

app = "Oracle JRockit";
types = make_list("JDK", "JRE");
kb_base = "SMB/Oracle_JRockit/";

# Establish a connection to the registry.
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# Get the paths of JRockit installs.
i = 0;
installs = make_list();
foreach type (types)
{
  # Construct the path to the base of the registry key for this type.
  base = "SOFTWARE\JRockit\Java ";
  if (type == "JDK")
    base += "Development Kit";
  else
    base += "Runtime Environment";

  # Get all the versions below the main key for this type of install.
  vers = get_registry_subkeys(handle:hklm, key:base);
  if (isnull(vers))
    continue;

  # Get the installation directory from each install.
  dirs = make_list();
  foreach ver (vers)
  {
    key = base + "\" + ver + "\JavaHome";
    dir = get_registry_value(handle:hklm, item:key);
    if (!isnull(dir))
      dirs = make_list(dirs, dir);
  }

  # There tend to be at least two version keys per install pointing to
  # the same directory, so collect all the dirs together and remove
  # the duplicates.
  dirs = list_uniq(dirs);

  # Store the installation dirs for version extraction.
  foreach dir (dirs)
    installs[i++] = make_list(type, dir);
}

# Tear down the connection to the registry.
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

if (i == 0)
  audit(AUDIT_NOT_INST, app);

# Get the version information for each install.
i = 0;
report = NULL;
foreach install (installs)
{
  type = install[0];
  dir = install[1];

  # The DLL we're looking for is a level deeper in the JDK, since it
  # keeps a subset of the JRE in a subdirectory.
  path = dir;
  if (type == "JDK")
    path += "\jre";

  # Get the version of a file that seems important.
  path += "\bin\jrockit\jvm.dll";
  ver = hotfix_get_fversion(path:path);
  if (ver["error"] != HCF_OK)
    continue;
  ver = join(ver["value"], sep:".");

  # Store the install for future plugins.
  kb_subkey = kb_base + type + "/";
  set_kb_item(name:kb_subkey + i + "/Version", value:ver);
  set_kb_item(name:kb_subkey + i + "/Path", value:dir);

  extra = make_array();
  extra["type"] = type;

  register_install(
    app_name:app,
    path:dir,
    version:ver,
    cpe:"cpe:/a:oracle:jrockit",
    extra:extra
    );

  i++;

  # Store that this type of JRockit is installed.
  replace_kb_item(name:kb_base + "Installed", value:TRUE);

}

hotfix_check_fversion_end();

if (i == 0)
  audit(AUDIT_NOT_INST, app);

report_installs(app_name: app, port:kb_smb_transport());
