#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31857);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/09/07 20:11:20 $");

  script_name(english:"Symantec AntiVirus Scan Engine Detection");
  script_summary(english:"Checks the version of Symantec AntiVirus Scan Engine.");

  script_set_attribute(attribute:"synopsis", value:
"An antivirus application is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"Symantec AntiVirus Scan Engine, a TCP/IP service with a programming
interface to allow integration with third-party products, is installed
on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://support.symantec.com/en_US/article.DOC2277.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:antivirus_scan_engine");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

#
include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");

# Figure out where the installer recorded information about it.

list = get_kb_list_or_exit("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");

installstring = NULL;
product_name  = NULL;

foreach name (keys(list))
{
  prod = list[name];
  if (prod && "Symantec AntiVirus Scan Engine" >< prod || "Symantec Scan Engine" >< prod || "Symantec Protection Engine" >< prod)
  {
   installstring = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
   installstring = str_replace(find:"/", replace:"\", string:installstring);
   product_name = prod;
   break;
  }
}

# default product name if none found in uninstall registry key
if (isnull(product_name)) product_name = "Symantec Scan Engine";

port = kb_smb_transport();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# SPE uses the same key as SSE, default to SSE if we dont have a Name
key = "SYSTEM\CurrentControlSet\Services\SYMCScan\DisplayName";
product_name = get_registry_value(handle:hklm, item:key);
if (isnull(product_name)) product_name = "Symantec Scan Engine";

key = "SYSTEM\CurrentControlSet\Services\SYMCScan\ImagePath";
path = get_registry_value(handle:hklm, item:key);

if (!isnull(path))
{
  path = str_replace(find:'"', replace:'', string:path);
  item = eregmatch(pattern:"^(.*\\)[^\\]+$", string:path);

  if(isnull(item) || isnull(item[1]))
    exit(1, "Unable to parse path from '" + key + "'.");

  path = item[1];
}

if (isnull(path) && isnull(installstring))
{
  RegCloseKey(handle:hklm);
  close_registry();
  audit(AUDIT_NOT_INST, "Symantec AntiVirus Scan Engine");
}

# try finding path through uninstall registry entry
if (isnull(path))
  path = get_registry_value(handle:hklm, item:installstring + '\\InstallLocation');

RegCloseKey(handle:hklm);
close_registry(close:FALSE);

if (!path)
 audit(AUDIT_NOT_INST, "Symantec AntiVirus Scan Engine");

if (path[strlen(path)-1] == '\\') exe = path + "symcscan.exe";
else exe = path + "\symcscan.exe";

ver = hotfix_get_fversion(path:exe);
hotfix_check_fversion_end();

if (ver['error'] == HCF_NOENT)
  audit(AUDIT_UNINST, "Symantec AntiVirus Scan Engine");
else if (ver['error'] != HCF_OK)
  audit(AUDIT_VER_FAIL, exe);

version = join(ver['value'], sep:'.');

set_kb_item(name:"SMB/symantec_scan_engine/Installed", value:TRUE);

set_kb_item(name:"Symantec/"+product_name+"/Version", value:version);
set_kb_item(name:"Symantec/"+product_name+"/Path", value:path);

# This will either set - Symantec/Symantec AntiVirus Scan Engine/Version
#>. or >.>.  Symantec/Symantec Scan Engine/Version

register_install(
  app_name:"Symantec AntiVirus Scan Engine",
  path:path,
  version:version,
  cpe:"cpe:/a:symantec:antivirus_scan_engine");

if (report_verbosity > 0)
{
  report =
     '\n  Product : ' + product_name +
     '\n  Path    : ' + path +
     '\n  Version : ' + version + '\n';
   security_note(port:port, extra:report);
}
else security_note(port:port);
