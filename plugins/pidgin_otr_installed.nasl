#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59194);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/08 22:04:50 $");

  script_name(english:"Pidgin OTR Plugin Detection");
  script_summary(english:"Detects Installs of Pidgin OTR Plugin");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a secure chat plugin for instant messaging
software installed."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has the Pidgin OTR (Off-the-Record) plugin installed.
This plugin allows for secure, encrypted communication between parties
using the Pidgin instant messaging software."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.cypherpunks.ca/otr/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:otr:pidgin-otr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "pidgin_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/Pidgin/Version");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("audit.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/Pidgin/Version");

appname = 'Pidgin OTR';

login  = kb_smb_login();
port = kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
pass   = kb_smb_password();
domain = kb_smb_domain();
name   =  kb_smb_name();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\pidgin-otr\UninstallString";

uninstall_path = get_registry_value(handle:hklm, item:key);

RegCloseKey(handle:hklm);

if (isnull(uninstall_path))
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}

# parse path
item = eregmatch(pattern: "([A-Za-z]:\\.*\\)[^\\]+\.exe", string: uninstall_path);
if (isnull(item))
{
  close_registry();
  exit(1, "Unable to parse path from the registry key [HKLM\" + key + "]");
}
path = item[1];

close_registry(close:FALSE);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

item = eregmatch(pattern: "[a-zA-Z]:(.*)", string: path);

# this error should not be possible, but check just in case
if (isnull(item))
{
  NetUseDel();
  exit(1, "Unexpected path format: '" + path + "'");
}

file = item[1] + "pidgin-otr.nsi";

fh = CreateFile(
  file:file,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

if (isnull(fh))
{
  NetUseDel();
  exit(1, "Unable to open '" + share[0] + ":" + file + "'");
}

file_content = "";
length = GetFileSize(handle:fh);
file_content = ReadFile(handle:fh, offset:0, length:length);

CloseFile(handle:fh);
NetUseDel();

if (file_content == "")
  exit(1, "Unable to read content from '" + share[0] + ":" + file + "'.");

#!define PRODUCT_VERSION "3.2.1-1"

item = eregmatch(pattern: 'PRODUCT_VERSION "([0-9\\.-]+)"', string: file_content);
if (isnull(item))
  exit(1, "Unable to parse version information in '" + share[0] + ":" + file + "'");
version = item[1];

kb_base = "SMB/Pidgin_OTR/";

set_kb_item(name:kb_base + "Installed", value:TRUE);
set_kb_item(name:kb_base + "Version", value:version);
set_kb_item(name:kb_base + "Path", value:path);

register_install(
  app_name:appname,
  path:path,
  version:version,
  cpe:"cpe:/a:otr:pidgin-otr");

if (report_verbosity > 0)
{
  report = '\n  Path    : ' + path +
           '\n  Version : ' + version + '\n';
  security_note(port:port,extra:report);
}
else security_note(port);
