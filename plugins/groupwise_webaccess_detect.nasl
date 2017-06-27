#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62415);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/08/03 14:40:24 $");

  script_name(english:"Novell GroupWise WebAccess Detection");
  script_summary(english:"Checks if GroupWise WebAccess is installed.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a remote access web application installed.");
  script_set_attribute(attribute:"description", value:
"Novell GroupWise WebAccess, a component of the GroupWise suite that
provides web-based remote access, is installed on the remote Windows
host.");
  script_set_attribute(attribute:"see_also", value:"https://www.novell.com/products/groupwise/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:groupwise_webaccess");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

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

# extracts version string from servlet class bytecode
# for 2012/2014 installs
function extract_version_string(class_blob)
{
  local_var i, start_pos, end_pos, tmp_str, item,
            ver_len, version;

  i = 0;
  i = stridx(class_blob, 'Application.version');
  if(i == -1) return NULL;

  # see if we can extract relevant portion of bytecode and extract version info
  start_pos = 0;
  if((i - 256) > 0) start_pos = i - 256;
  end_pos = i + strlen('Application.version') - 1;
  if(end_pos >= strlen(class_blob)) end_pos = strlen(class_blob) - 1;

  tmp_str = substr(class_blob, start_pos, end_pos);
  # search backwards for version string
  for(i = strlen(tmp_str) - 1; i>=0; i--)
  {
    if(tmp_str[i] != '\x01' || tmp_str[i+1] != '\x00') continue;
    ver_len = ord(tmp_str[i+2]);

    if((ver_len + 3 + i) > strlen(tmp_str)) continue;

    version = substr(tmp_str, i + 3, i + 3 + ver_len - 1);

    if(version =~ "^[0-9]+\.[0-9]+\.[0-9.]+$") return version;
  }
  return NULL;
}

service = NULL;
version = NULL;
path = NULL;

app = 'GroupWise WebAccess';
port = kb_smb_transport();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\NOVELL\GroupWise WebAccess\ServiceNames";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i < info[0]; i++)
  {
    value = RegEnumValue(handle:key_h, index:i);
    # WebAccess (WEBAC80A)
    if (strlen(value[1]) && 'WebAccess' >< value[1])
    {
      service = value[1];
      break;
    }
  }
  RegCloseKey(handle:key_h);
}

if (isnull(service))
{
  display_names = get_kb_list_or_exit('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');
  path = NULL;
  foreach key (keys(display_names))
  {
    if("GroupWise WebAccess" >!< display_names[key]) continue;
    key = key - 'SMB/Registry/HKLM/' - 'DisplayName';
    key += "InstallLocation";
    key = str_replace(string:key, find:'/', replace:"\");
    path = get_registry_value(handle:hklm, item:key);
    if(isnull(path)) continue;

    servlet_path = ereg_replace(pattern:"^(.*)\\[^\\]+\\$",
      replace:"\1\tomcat6\webapps\gw\WEB-INF\classes\com\novell\webaccess\WebAccessServlet.class",
      string:path
    );
    file = hotfix_get_file_contents(path:servlet_path);
    contents = file["data"];

    hotfix_handle_error(
      error_code   : file["error"],
      file         : servlet_path,
      appname      : app,
      exit_on_fail : TRUE
    );

    hotfix_check_fversion_end();
    version = extract_version_string(class_blob:contents);
    break;
  }

  if(isnull(version))
  {
    RegCloseKey(handle:hklm);
    close_registry();
    audit(AUDIT_NOT_INST, app);
  }
}
else
{
  key = "SYSTEM\CurrentControlSet\Services\Eventlog\Application\\" + service + "\EventMessageFile";
  path = get_registry_value(handle:hklm, item:key);
  if (!isnull(path))
    path = ereg_replace(pattern:'["]*'+"([A-Za-z]:.*)\\[^\\]+" + '["]*', replace:"\1", string:path);

  RegCloseKey(handle:hklm);

  if (isnull(path))
  {
    close_registry();
    audit(AUDIT_NOT_INST, app);
  }
  close_registry(close:FALSE);


  exe = path + "\GWINTER.exe";
  ver = hotfix_get_fversion(path:exe);

  hotfix_handle_error(
    error_code   : ver["error"],
    file         : exe,
    appname      : app,
    exit_on_fail : TRUE
  );
 
  hotfix_check_fversion_end();

  version = join(sep:'.', ver['value']);
}

set_kb_item(name:'SMB/'+app+'/Path', value:path);
set_kb_item(name:'SMB/'+app+'/Version', value:version);

extra = NULL;
if(!isnull(service))
{
  set_kb_item(name:'SMB/'+app+'/Service', value:service);
  extra = make_array('Service', service);
}

register_install(
  app_name:app,
  path:path,
  version:version,
  extra:extra,
  cpe:"cpe:/a:novell:groupwise_webaccess"
);

report_installs(app_name:app);
