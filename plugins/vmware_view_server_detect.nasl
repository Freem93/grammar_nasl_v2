#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63682);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/07/12 02:12:33 $");

  script_name(english:"VMware View Server Detection");
  script_summary(english:"Detects if VMware View Server installed");

  script_set_attribute(attribute:"synopsis", value:"An OS virtual desktop solution is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"VMware View Server, formerly known as VMware Virtual Desktop
Infrastructure, is installed on the remote host.  VMware View Server is
an OS virtual desktop solution for personalized virtual desktops as a
managed service from a virtualized platform.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/products/view/overview.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:view");
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
include("smb_reg_query.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("install_func.inc");

appname = "VMware View Server";

registry_init();
handle = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\VMware, Inc.\VMware VDM";
item =  get_values_from_key(handle:handle, key:key, entries:make_list('ServerInstallPath'));
path = item['ServerInstallPath'];
RegCloseKey(handle:handle);
if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
close_registry(close:FALSE);
filePath =  path + "bin\wsnm.exe";

ver = hotfix_get_fversion(path:filePath);
hotfix_check_fversion_end();
if (ver['error'] == HCF_NOENT) audit(AUDIT_UNINST, appname);
else if(ver['error'] != HCF_OK) audit(AUDIT_VER_FAIL, filePath);

version = join(ver['value'], sep:'.');

port = kb_smb_transport();
set_kb_item(name:"VMware/ViewServer/Installed", value:TRUE);
set_kb_item(name:"VMware/ViewServer/Version", value:version);
set_kb_item(name:"VMware/ViewServer/Path", value:path);

register_install(
  app_name:appname,
  path:path,
  version:version,
  cpe:"cpe:/a:vmware:view");

if (report_verbosity> 0)
{
 report =
   '\n  Path    : ' + path +
   '\n  Version : ' + version + '\n';
 security_note(port:port, extra:report);
}
else security_note(port);
