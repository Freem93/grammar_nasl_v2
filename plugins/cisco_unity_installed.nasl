#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70169);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/12 02:12:33 $");

  script_name(english:"Cisco Unity Detection");
  script_summary(english:"Detects installs of Cisco Unity through SMB");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has page communications integration software
installed.");
  script_set_attribute(attribute:"description", value:
"The remote host has Cisco Unity installed.  Cisco Unity is
communication integration software that bridges phone systems to
email.");
  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/sw/voicesw/ps2237/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unity");
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

app = "Cisco Unity";

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Active Voice\CommServer\1.0\Root Path";

path = get_registry_value(handle:hklm, item:key);

RegCloseKey(handle:hklm);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}

close_registry(close:FALSE);

path = ereg_replace(string:path, pattern:"^(.*)\\$", replace:"\1");
file = path + "\Web\SAHelp\LocalizationFiles\ENU\SAPageHelp\SystemAdmin\SysMsgSubjsBody.html";
html = hotfix_get_file_contents(file);
NetUseDel();

if (html["error"] != HCF_OK)
{
  if (html["error"] == HCF_NOENT) audit(AUDIT_UNINST, app);
  exit(1, "Error obtaining the version of '" + file + "'.");
}
html = html["data"];

matches = eregmatch(string:html, pattern:"after upgrading to Cisco Unity ([^<]+)\.</p>");
if (isnull(matches)) exit(1, "Failed to parse the version from '" + path + "'.");
ver = matches[1];

kb_base = "SMB/Cisco_Unity/";
set_kb_item(name:kb_base + "Installed", value:TRUE);
set_kb_item(name:kb_base + "Version", value:ver);
set_kb_item(name:kb_base + "Path", value:path);

register_install(
  app_name:app,
  path:path,
  version:ver,
  cpe:"cpe:/a:cisco:unity");

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + ver +
    '\n';
}

security_note(port:get_kb_item("SMB/transport"),  extra:report);
