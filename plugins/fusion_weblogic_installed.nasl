#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57793);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/05/14 17:10:41 $");

  script_name(english:"Oracle Fusion Middleware WebLogic Detection (credentialed check)");
  script_summary(english:"Checks for Oracle Fusion Middleware WebLogic.");

  script_set_attribute(attribute:"synopsis", value:
"A web application server is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"Oracle WebLogic, a Java EE application, is installed on the remote
host as an Oracle Fusion Middleware component.");
  # http://www.oracle.com/technetwork/middleware/weblogic/overview/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99924a19");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");
include("audit.inc");
include("smb_reg_query.inc");

report_info = "";
install_num = 0;

get_kb_item_or_exit('SMB/Registry/Enumerated');
name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();


# Connect to IPC share on machine
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

# Connect to registry on machine
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

display_names = get_kb_list_or_exit('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');

fusion_installs = make_array();

foreach key (keys(display_names))
{
  display_name = display_names[key];
  if (tolower(display_name) !~ "oracle weblogic")
    continue;

  key = key - 'SMB/Registry/HKLM/' - 'DisplayName';
  key = str_replace(string:key, find:'/', replace:"\");
  key += 'UninstallString';
  path = get_registry_value(handle:hklm, item:key);
  if (!isnull(path))
    fusion_installs[display_name] = path;
}

# this key will only exist in the registry if addtional
# fusion components are installed with WebLogic
key = 'SOFTWARE\\ORACLE';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

oracle_homes = make_list();

if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  if(isnull(info))
  {
    NetUseDel();
    RegCloseKey(handle:hklm);
    exit(1, "Unable to to obtain registry key information.");
  }
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (tolower(subkey) =~ "KEY_OH.*") {
      key2 = key + '\\' + subkey;
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        value = RegQueryValue(handle:key2_h, item:"ORACLE_HOME");
        if (!isnull(value[1]))
          oracle_homes = make_list(oracle_homes, value[1]);
        RegCloseKey(handle:key2_h);
      }
      else
      {
        NetUseDel();
        RegCloseKey(handle:key_h);
        RegCloseKey(handle:hklm);
        exit(1, "Unable to open ORACLE_HOME registry value.");
      }
    }
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (max_index(keys(fusion_installs)) == 0)
{
  NetUseDel();
  audit(AUDIT_NOT_INST, "Oracle Fusion Middleware WebLogic Server");
}

foreach install (keys(fusion_installs))
{
  uninstall_path = fusion_installs[install];
  middleware_path = "";
  # C:\Oracle\Middleware\wlserver_10.3\uninstall\uninstall.cmd
  middleware_path = ereg_replace(pattern:".*([A-Za-z]:.*\\).*\\uninstall\\.*", replace:"\1", string:uninstall_path);

  if (middleware_path == "")
    continue;

  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:middleware_path);

  NetUseDel(close:FALSE);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, "Can't connect to '" + share + "' share.") ;
  }

  xml_file = ereg_replace(pattern:"^[A-Za-z]:(.*)\\?", replace:"\1\registry.xml", string:middleware_path);

  fh = CreateFile(
    file:xml_file,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  xml_content = "";

  # WebLogic might be installed, but it's not as a fusion product if registry.xml is missing,
  # so we move on to the next candidate in that case
  if (isnull(fh))
    continue;

  length = GetFileSize(handle:fh);
  xml_content = ReadFile(handle:fh, offset:0, length:length);
  CloseFile(handle:fh);
  # this file should not be empty
  if(xml_content == "")
  {
    NetUseDel();
    exit(1, "Unable to obtain contents of registry.xml for Fusion Middleware installed at " + middleware_path + ".");
  }

  product_parse = FALSE;
  version_src = "";
  server_src = "";

  foreach line (split(xml_content, sep:'\n', keep:FALSE))
  {
    if (eregmatch(pattern:'<product[^>]*name=\"WebLogic Platform\"[^>]*>', string:line))
       product_parse = TRUE;
    if (eregmatch(pattern:'</product>', string:line) && product_parse)
      break;
    item = eregmatch(pattern:'<release [^>]*>', string:line);
    if (!isnull(item) && product_parse)
      version_src = item[0];
    item = eregmatch(pattern:'<component[^>]*name=\"WebLogic Server\"[^>]*>', string:line);
    if (!isnull(item) && product_parse)
      server_src = item[0];
  }

  # this shoud be considered an error...
  if (version_src == "" || server_src == "")
  {
    NetUseDel();
    exit(1, 'Unable to extract release or server information from registry.xml.');
  }

  # check to make sure product is completely installed
  item = eregmatch(pattern:'Status=\"([^\"]+)\"', string:version_src);
  if (tolower(item[1]) != 'installed')
    continue;

  # get server path
  # Luckily, only one WebLogic install is possible per Middleware Home
  item = eregmatch(pattern:'InstallDir=\"([^\"]+)\"', string: server_src);
  if (!isnull(item[1]))
    server_path = item[1];
  else
  {
    NetUseDel();
    exit(1, "Unable to extract WebLogic Server path from registry.xml.");
  }
  # grab a list of bug fixes
  bug_fixes = make_list();

  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:server_path);
  NetUseDel(close:FALSE);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, "Can't connect to '" + share + "' share.") ;
  }

  dir = ereg_replace(pattern:"^[A-Za-z]:(.*)\\?", replace:"\1\bugsfixed", string:server_path);
  fh = FindFirstFile(pattern:dir + "\*-WLS-*");

  while (!isnull(fh[1]))  # loops over each file found in the directory that matches 'pattern'
  {
    item = eregmatch(pattern:"^([0-9]+)-WLS", string:fh[1]);
    if (!isnull(item[1]))
       bug_fixes = make_list(bug_fixes, item[1]);
    fh = FindNextFile(handle:fh);  # gets the next file in the directory
  }
  # Remove duplicates
  bug_fixes = list_uniq(bug_fixes);

  version = NULL;
  sp_level = NULL;
  patch_level = NULL;

  # parse version level
  item = eregmatch(pattern:'level=\"([0-9\\.]+)\"', string:version_src);
  if (!isnull(item[1]))
    version = item[1];

  # parse service pack level
  item = eregmatch(pattern:'ServicePackLevel=\"([0-9\\.]+)\"', string:version_src);
  if (!isnull(item[1]))
    sp_level = item[1];

  # parse patch level
  item = eregmatch(pattern:'PatchLevel=\"([0-9\\.]+)\"', string:version_src);
  if (!isnull(item[1]))
    patch_level = item[1];

  # stores a list of oracle homes associated with this fusion install
  fusion_oracle_homes = make_list();

  # verify oracle home directories
  foreach home (oracle_homes)
  {
    # see if home directory is installed as a component of this
    # middleware fusion home
    if(middleware_path >!< home)
      continue;

    # if it's a completely functional home, it will have a
    # inventory\ContentsXML\comps.xml
    share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:home);
    NetUseDel(close:FALSE);
    rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if (rc != 1)
    {
      NetUseDel();
      exit(1, "Can't connect to '" + share + "' share.") ;
    }

    xml_file = ereg_replace(pattern:"^[A-Za-z]:(.*)\\?", replace:"\1\inventory\ContentsXML\comps.xml", string:home);
    fh = CreateFile(
      file:xml_file,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );

    if(!isnull(fh))
      fusion_oracle_homes = make_list(fusion_oracle_homes, home);
  }

  if (!isnull(version) && !isnull(sp_level) && !isnull(patch_level))
  {
    install_num ++;
    report_info += '\n\nFusion Middleware path : ' + middleware_path;
    report_info += '\n  WebLogic Server path : ' + server_path;
    report_info += '\n  Version source       : \n' + version_src;
    report_info += '\n  Version              : ' + version;
    report_info += '\n  Service pack         : ' + sp_level;
    report_info += '\n  Patch level          : ' + patch_level;

    # makes looping through installs in plugins easier
    set_kb_item(name:"SMB/WebLogic_Fusion/" + install_num + "/Install_Num", value:install_num);

    set_kb_item(name:"SMB/WebLogic_Fusion/" + install_num + "/FusionPath", value:middleware_path);
    set_kb_item(name:"SMB/WebLogic_Fusion/" + install_num + "/ServerPath", value:server_path);
    set_kb_item(name:"SMB/WebLogic_Fusion/" + install_num + "/Version", value:version);
    set_kb_item(name:"SMB/WebLogic_Fusion/" + install_num + "/ServicePack", value:sp_level);
    set_kb_item(name:"SMB/WebLogic_Fusion/" + install_num + "/PatchLevel", value:patch_level);
    if (max_index(bug_fixes) > 0)
    {
      report_info += '\n  Bug fixes            : ';
      foreach fix (bug_fixes)
      {
        set_kb_item(name:"SMB/WebLogic_Fusion/" + install_num + "/bugfixes/" + fix, value:TRUE);
        report_info += '\n    ' + fix;
      }
    }
    if (max_index(fusion_oracle_homes) > 0)
    {
      report_info += '\n  Component home directories : ';
      i = 0;
      foreach home (fusion_oracle_homes)
      {
        set_kb_item(name:"SMB/WebLogic_Fusion/" + install_num + "/comp_homes/" + i, value:home);
        i++;
        report_info += '\n    ' + home;
      }
    }
  }
}

# Cleanup
NetUseDel();

if(install_num > 0)
{
  set_kb_item(name:"SMB/WebLogic_Fusion/Installed", value:TRUE);
  if(install_num == 1)
    report = '\nThe following Fusion Middleware WebLogic install was found :' + report_info + '\n';
  else
    report = '\nThe following Fusion Middleware WebLogic installs were found :' + report_info + '\n';

  if (report_verbosity > 0)
    security_note(port:port, extra:report);
  else security_note(port);

  exit(0);
}
  else exit(0, "No Middleware Fusion Oracle WebLogic installs were found.");
