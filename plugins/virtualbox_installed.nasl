#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40548);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/23 16:47:50 $");

  script_name(english:"Oracle VM VirtualBox Detection");
  script_summary(english:"Checks for a VirtualBox install.");

  script_set_attribute(attribute:"synopsis", value:
"A virtualization application is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"Oracle VM VirtualBox, formerly Sun xVM VirtualBox, a free
virtualization application, is installed on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www.virtualbox.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:vm_virtualbox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app = 'Oracle VM VirtualBox';
path = NULL;

keys = make_list(
  "SOFTWARE\Sun\xVM VirtualBox",
  "SOFTWARE\Sun\VirtualBox",
  "SOFTWARE\Oracle\VirtualBox"
);

index = 0;

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

while (isnull(path) && index < max_index(keys))
{
  key = keys[index] + "\InstallDir";

  path = get_registry_value(handle:hklm, item:key);

  index++;
}
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

if (isnull(path)) audit(AUDIT_NOT_INST, app);

# Try to get the version from the VirtualBox.exe
# If that fails try to get it from VirtualBox.dll

exe = path + "VirtualBox.exe";

ver = hotfix_get_pversion(path:exe);

if (ver['error'] != 0)
{
  dll = path + "VirtualBox.dll";

  ver = hotfix_get_pversion(path:dll);

  if (ver['error'] != 0)
  {
    hotfix_check_fversion_end();
    exit(1, "We could not get a version from either VirtualBox.exe or VirtualBox.dll");
  }
}

hotfix_check_fversion_end();

version = join(sep:".", ver["value"]);

port = kb_smb_transport();

if (version)
{
  set_kb_item(name:"VirtualBox/Version", value:version);
  set_kb_item(name:"SMB/VirtualBox/" + version, value:path);

  register_install(
    app_name:app,
    path:path,
    version:version,
    cpe:"cpe:/a:oracle:vm_virtualbox");

  report_installs();
}
else audit(AUDIT_UNKNOWN_APP_VER, app);
