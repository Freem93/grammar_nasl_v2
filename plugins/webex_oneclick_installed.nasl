#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69274);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/12 02:12:34 $");

  script_name(english:"Cisco WebEx One-Click Detection");
  script_summary(english:"Detects installs of WebEx One-Click");

  script_set_attribute(attribute:"synopsis", value:"The remote host has internet meeting software installed.");
  script_set_attribute(attribute:"description", value:
"The remote host has Cisco WebEx One-Click installed.  WebEx One-Click
is a desktop client for WebEx's meeting software.");
  script_set_attribute(attribute:"see_also", value:"http://www.webex.com/");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:webex:oneclick");
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

app = "WebEx One-Click";

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\WebEx\ProdTools\Path";

path = get_registry_value(handle:hklm, item:key);

RegCloseKey(handle:hklm);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}

close_registry(close:FALSE);

path = ereg_replace(string:path, pattern:"^(.*)\\$", replace:"\1");
exe = path + "\ptoneclk.exe";
ver = hotfix_get_fversion(path:exe);

if (ver["error"] != HCF_OK)
{
  NetUseDel();
  if (ver["error"] == HCF_NOENT)
     audit(AUDIT_UNINST, app);
  exit(1, "Error obtaining the version of '" + exe + "'.");
}

hotfix_check_fversion_end();

version = join(ver["value"], sep:".");

kb_base = "SMB/WebEx_OneClick/";
set_kb_item(name:kb_base + "Installed", value:TRUE);
set_kb_item(name:kb_base + "Version", value:version);
set_kb_item(name:kb_base + "Path", value:path);

register_install(
  app_name:app,
  path:path,
  version:version,
  cpe:"x-cpe:/a:webex:oneclick");

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version +
    '\n';
}

security_note(port:kb_smb_transport(),  extra:report);
