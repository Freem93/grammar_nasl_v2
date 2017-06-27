#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64567);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/07/12 02:12:34 $");

  script_name(english:"IBM Tivoli Storage Manager Client Installed");
  script_summary(english:"Checks for Tivoli Storage Manager Client");

  script_set_attribute(attribute:"synopsis", value:
"A client for a backup management application is installed on the remote
Windows host.");
  script_set_attribute(attribute:"description", value:
"Tivoli Storage Manager Client, a client for Tivoli Storage Manager, is
installed on the remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"http://www-142.ibm.com/software/products/us/en/tivostormana/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager_client");
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

app = 'Tivoli Storage Manager Client';
kb_base = 'SMB/' + app + '/';
port = kb_smb_transport();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\IBM\ADSM\CurrentVersion\TSMClientPath";
path = get_registry_value(handle:hklm, item:key);

if (isnull(path))
{
  # Older versions store the path under the Path key instead of TSMClientPath
  key = "SOFTWARE\IBM\ADSM\CurrentVersion\Path";
  path = get_registry_value(handle:hklm, item:key);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}

path += "baclient";
exe = path + "\dsmc.exe";
ver = hotfix_get_fversion(path:exe);

if (ver['error'] == HCF_NOENT)
{
  hotfix_check_fversion_end();
  audit(AUDIT_UNINST, app);
}
else if (ver['error'] != HCF_OK)
{
  hotfix_check_fversion_end();
  audit(AUDIT_VER_FAIL, path);
}

# Check if the webgui is installed.  Just have to make
# sure the file exists
ver2 = hotfix_get_fversion(path:path + "\dsmagent.exe");
if (ver2['error'] != HCF_NOENT)
  set_kb_item(name:kb_base+'WebGUI', value:TRUE);

hotfix_check_fversion_end();
version = join(ver['value'], sep:'.');
set_kb_item(name:kb_base+'Path', value:path);
set_kb_item(name:kb_base+'Version', value:version);

register_install(
  app_name:app,
  path:path,
  version:version,
  cpe:"cpe:/a:ibm:tivoli_storage_manager_client");

if (report_verbosity > 0)
{
  report +=
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
