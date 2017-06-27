#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(66554);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/12 02:12:33 $");

  script_name(english:"BitZipper Installed");
  script_summary(english:"Checks for a BitZipper install");

  script_set_attribute(attribute:"synopsis", value:"A data compression tool is installed on the remote host.");
  script_set_attribute(attribute:"description", value:"BitZipper, a data compression tool, is installed on the remote host.");

  script_set_attribute(attribute:"see_also", value:"http://www.bitzipper.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bitberry_software:bitzipper");
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
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("install_func.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');

appname = "BitZipper";
registry_init();
handle = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Classes\CLSID\{D5906221-A717-479b-9B49-CD848F9CE816}\InprocServer32";
item = get_values_from_key(handle:handle, key:key, entries:make_list(""));
item = item[''];
match = eregmatch(string:item, pattern:"([A-Za-z]:\\.*\\)([^\\]+\.(exe|dll))");
path = NULL;
if(!isnull(match))
{
  path = match[1];

}
else
{
  list = get_kb_list_or_exit("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
  foreach name (keys(list))
  {
    prod = list[name];
    if("BitZipper" >< prod)
    {
      installstring = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
      key = str_replace(find:"/", replace:"\", string:installstring);
    }
  }
  item = get_values_from_key(handle:handle, key:key, entries:make_list("InstallLocation"));
  path = item['InstallLocation'];
}
RegCloseKey(handle:handle);
if(isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
else close_registry(close:FALSE);

filePath = path + "BITZIPPER.exe";
ver = hotfix_get_fversion(path:filePath);
hotfix_check_fversion_end();

if (ver['error'] == HCF_NOENT) audit(AUDIT_UNINST, appname);
else if(ver['error'] != HCF_OK) audit(AUDIT_VER_FAIL, filePath);
else ver = ver['value'];

version = join(ver, sep:".");

port = kb_smb_transport();
kb_base = "SMB/bitberry_bitzipper/";

set_kb_item(name:kb_base + "Installed", value:TRUE);
set_kb_item(name:kb_base + "Path", value:path);
set_kb_item(name:kb_base + "Version", value:version);

register_install(
  app_name:appname,
  path:path,
  version:version,
  cpe:"cpe:/a:bitberry_software:bitzipper");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
