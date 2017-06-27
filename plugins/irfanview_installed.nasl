#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57559);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/07/12 02:12:32 $");

  script_name(english:"IrfanView Detection");
  script_summary(english:"Checks for IrfanView");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host has a graphic viewer installed.");
  script_set_attribute(attribute:"description", value:"IrfanView, a graphic viewer, is installed on the remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"http://www.irfanview.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:irfanview:irfanview");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("audit.inc");
include("install_func.inc");

appname = "IrfanView";

# recursive function to traverse directory and
# get a list of files
function get_file_list(dir, pattern, max_depth)
{
  local_var retx, file_list, dir_list, r_file_list, r_dir;
  if(max_depth < 0)
    return NULL;

  retx = FindFirstFile(pattern:dir + "\*");
  file_list = make_list();
  dir_list = make_list();

  while(!isnull(retx[1]))
  {
    if(retx[2] & FILE_ATTRIBUTE_DIRECTORY && retx[1] != '.' && retx[1] != '..')
      dir_list = make_list(dir_list, retx[1]);
    else
    {
      if(retx[1] =~ pattern)
        file_list = make_list(file_list, dir + "\" + retx[1]);
    }
    retx = FindNextFile(handle:retx);
  }

  foreach r_dir (dir_list)
  {
    r_file_list = get_file_list(dir:dir + "\" + r_dir, pattern: pattern, max_depth: max_depth - 1);
    if(r_file_list != NULL)
      file_list = make_list(file_list, r_file_list);
  }

  return file_list;
}

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

path = NULL;
key = 'SOFTWARE\\Classes\\IrfanView\\shell\\open\\command\\';

path = get_registry_value(handle:hklm, item:key);

RegCloseKey(handle:hklm);

if(isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}

item = eregmatch(pattern:'"*([A-Za-z]:.*)\\\\[^\\\\]+["]*', string:path);

if(isnull(item[1]))
{
  close_registry();
  exit(1, "Unable to parse path from registry key [" + key + "]");
}

path = item[1];

close_registry(close:FALSE);

ver = hotfix_get_fversion(path:path + "\i_view32.exe");

if (ver['error'] != HCF_OK)
{
  NetUseDel();

  # file does not exist, so application must have been
  # uninstalled uncleanly
  if(ver['error'] == HCF_NOENT)
     audit(AUDIT_UNINST, appname);

  # other error
  exit(1, "Error obtaining version of '" + path + "\i_view32.exe'");
}

version = join(ver['value'], sep:'.');

NetUseDel(close: FALSE);

login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
port = kb_smb_transport();

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

plugin_dir = ereg_replace(pattern:'[A-Za-z]:(.*)', replace:'\\1\\Plugins', string:path);

file_list = get_file_list(dir:plugin_dir, pattern: "\.dll$", max_depth: 2);
plugin_dir += "\";

NetUseDel(close: FALSE);

foreach file (file_list)
{
  ver = hotfix_get_fversion(path:(share - '$')+ ":" + file);
  if(!isnull(ver['value']))
  {
    str_ver = join(sep: '.', ver['value']);

    filename = file - plugin_dir;
    set_kb_item(name: 'SMB/IrfanView/Plugin_Version/' + filename, value:str_ver);
  }
}

hotfix_check_fversion_end();

set_kb_item(name:'SMB/IrfanView/Version', value:version);
set_kb_item(name:'SMB/IrfanView/Path', value:path);

register_install(
  app_name:appname,
  path:path,
  version:version,
  cpe:"cpe:/a:irfanview:irfanview");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
