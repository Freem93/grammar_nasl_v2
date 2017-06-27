#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58652);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/07/29 18:53:53 $");

  script_name(english:"Microsoft BizTalk Server Installed");
  script_summary(english:"Checks registry/filesystem for BizTalk Server.");

  script_set_attribute(attribute:"synopsis", value:
"An enterprise service bus is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"Microsoft BizTalk Server, an enterprise service bus, is installed on
the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://www.microsoft.com/en-us/cloud-platform/biztalk");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:biztalk_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
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

appname  = 'BizTalk Server';
names    = get_kb_list_or_exit('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');
files    = make_list("\\BTSNTSvc.exe", "\\BTS_SvcPW.exe");
installs = 0;
found    = make_array();

foreach kb_key (keys(names))
{
  name = names[kb_key];
  if (name !~ '^Microsoft BizTalk Server [0-9]+( R2)?$') continue;

  kb_key = kb_key - 'DisplayName' + 'InstallLocation';
  path   = get_kb_item(kb_key);
  if (empty_or_null(path) || found[path]) continue;

  version = NULL;
  foreach file (files)
  {
    file_path = path + file;
    ver_check = hotfix_get_fversion(path:file_path);
    error = hotfix_handle_error(error_code:ver_check['error'], file:file_path);
    if (!error)
    {
      v = ver_check['value'];
      version = v[0]+'.'+v[1]+'.'+v[2]+'.'+v[3];
    }

    # If the file exists but we didn't get a version, this still confirms the installation is present
    else if ("Failed to get the file version" >< error)
      version = UNKNOWN_VER;

    # For file-related errors, continue to try next file
    else if ("does not exist" >< error || "Unable to parse pathname" >< error || "Unknown error when attempting to access" >< error)
      continue;

    # For access-related errors, exit
    else if ("Error connecting" >< error || "Error accessing" >< error || "Failed to connect" >< error)
      exit(1, error);

    installs++;
    found[path] = TRUE;

    # BizTalk Server 2006 R2 doesn't have R2 in its DisplayName
    if ( "2006" >< name && ver_compare(ver:version, fix:"3.6.1404.0") >= 0 && "R2" >!< name )
      name += " R2";

    register_install(
      app_name:appname,
      path:path,
      version:version,
      extra:make_array("Product Name", name),
      cpe:"cpe:/a:microsoft:biztalk_server"
    );
    break;
  }
}

hotfix_check_fversion_end();

if (installs == 0)
  audit(AUDIT_UNINST, appname);

report_installs(app_name:appname, port:kb_smb_transport());
