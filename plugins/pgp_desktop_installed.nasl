#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64852);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/12 02:12:33 $");

  script_name(english:"Symantec Encryption Desktop Detection");
  script_summary(english:"Checks for Symantec Encryption Desktop installs");

  script_set_attribute(attribute:"synopsis", value:"The remote host has a desktop encryption application installed.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has Symantec Encryption Desktop installed (formerly PGP
Desktop), a desktop encryption application."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/encryption");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:encryption_desktop");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pgp:desktop_for_windows");
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

app = 'Symantec Encryption Desktop';
kb_base = "SMB/symantec_encryption_desktop/";

port = kb_smb_transport();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\PGP Corporation\PGP\INSTALLPATH";
path = get_registry_value(handle:hklm, item:key);

RegCloseKey(handle:hklm);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}

close_registry(close:FALSE);

if (path[strlen(path)-1] == '\\') exe1 = path + "pgpdesk.exe";
else exe1 = path + "\pgpdesk.exe";

# the install can be split across program file directories
# on 64-bit architectures
# ('Program Files' and 'Program Files x86')
# so we search all possible locations for pgpdesk.exe
exe2 = NULL;

if (
  tolower(hotfix_get_programfilesdir()) >< tolower(exe1) &&
  !isnull(hotfix_get_programfilesdir()) &&
  !isnull(hotfix_get_programfilesdirx86())
)
{
  exe2 = tolower(exe1) - tolower(hotfix_get_programfilesdir());
  exe2 = hotfix_get_programfilesdirx86() + exe2;
}

# disk encryption driver location
driver = NULL;
winroot = hotfix_get_systemroot();
if (winroot) driver =  winroot + "\system32\drivers\pgpdisk.sys";

exe_list = make_list(exe1);
if (!isnull(exe2)) exe_list = make_list(exe_list, exe2);

version = NULL;
check_file = '';
foreach exe (exe_list)
{
  ver = hotfix_get_fversion(path:exe);
  if (ver['error'] == HCF_OK)
  {
    check_file = exe;
    version = join(ver['value'], sep:'.');
    break;
  }
}

# get driver version directly,
# should be the same as pgpdesk.exe
ver = hotfix_get_fversion(path:driver);
if (ver['error'] == HCF_OK)
{
  driver_version = join(ver['value'], sep:'.');
  if(isnull(version))
  {
    version = driver_version;
    check_file = driver;
  }
  set_kb_item(name:kb_base+'DriverVersion', value:version);
  set_kb_item(name:kb_base+'DriverPath', value:driver);
}

hotfix_check_fversion_end();

if (isnull(version)) audit(AUDIT_UNINST, app);

set_kb_item(name:kb_base+'Path', value:path);
set_kb_item(name:kb_base+'Version', value:version);
set_kb_item(name:kb_base+'CheckFile', value:check_file);

register_install(
  app_name:app,
  path:path,
  version:version,
  extra:make_array('CheckFile', check_file),
  cpe:"cpe:/a:symantec:encryption_desktop");

if (report_verbosity > 0)
{
  report +=
    '\n  Path         : ' + path +
    '\n  Version      : ' + version + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
