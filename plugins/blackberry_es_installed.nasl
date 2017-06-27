#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20949);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/06/06 15:56:50 $");

  script_name(english:"BlackBerry Enterprise Service 10 / BlackBerry Enterprise Server / BlackBerry Unite! Detection");
  script_summary(english:"Detects BlackBerry Enterprise Service 10 / BlackBerry Enterprise Server / Unite!");

  script_set_attribute(attribute:"synopsis", value:
"A messaging service is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"BlackBerry Enterprise Service 10, BlackBerry Enterprise Server, or
BlackBerry Unite! is installed on the remote host. These applications
are software suites for linking wireless networks and devices with
messaging and application servers.");
  script_set_attribute(attribute:"see_also", value:"http://us.blackberry.com/enterprise/products/bes12.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:blackberry:blackberry_enterprise_service");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rim:blackberry_enterprise_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_reg_query.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

# Get some info about the install.
path = NULL;
prod_ver = NULL;
subkey = NULL;

key = "SOFTWARE\Research In Motion\BlackBerry Enterprise Server\Setup";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"BasePath");
  if (!isnull(item))
  {
    path = item[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }

  # nb: this leads to the actual product installed, including any
  # service packs / hotfixes.
  item = RegQueryValue(handle:key_h, item:"ConfigProductCode");
  if (!isnull(item)) subkey = item[1];

  item = RegQueryValue(handle:key_h, item:"ProductVersion");
  if (!isnull(item)) prod_ver = item[1];

  RegCloseKey(handle:key_h);
}

# Check for BlackBerry Attachment Server
attachserver = FALSE;
key = "SOFTWARE\Research In Motion\BBAttachServer";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"ServiceType");
  if (!isnull(item)) attachserver = TRUE;

  RegCloseKey(handle:key_h);
}

if (!isnull(path) && !isnull(subkey))
{
  # Get info about the current install.
  key = string("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/", subkey, "/DisplayName");
  name = get_kb_item(key);

  if ("Unite!" >< name && !isnull(prod_ver))
  {
    ver = prod_ver;
  }
  else
  {
    key = string("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/", subkey, "/DisplayVersion");
    ver = get_kb_item(key);
  }
}

# Check for BlackBerry Enterprise Service 10+
key = "SOFTWARE\Research In Motion\BlackBerry Enterprise Service\Setup";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"ConfigDLLPath");
  if (!isnull(item))
  {
    path = item[1];
    path = ereg_replace(pattern:"^(.+)\\ConfigTool\\$", replace:"\1", string:path);
  }

  item = RegQueryValue(handle:key_h, item:"InstallVersion");
  if (!isnull(item)) ver = item[1];

  name = "BlackBerry Enterprise Service";

  RegCloseKey(handle:key_h);
}

# Check for BlackBerry Enterprise Service 12.x
key = "SOFTWARE\BlackBerry\BES12";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallationFolder");
  if (!isnull(item))
    path = item[1];

  item = RegQueryValue(handle:key_h, item:"MarketingVersion");
  if (!isnull(item)) ver = item[1];

  RegCloseKey(handle:key_h);

  # Newer versions of BES12 do not seem to have the above registry values -- check uninstall info
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\BES12";
  if (empty_or_null(path))
  {
    item = get_registry_value(handle:hklm, item:key + "\InstallLocation");
    if (!empty_or_null(item))
    {
      # The path appears with backslashes instead of forward slashes (e.g. C:/Program Files/BES)
      path = str_replace(string:item, find:"/", replace:"\");  
    }
  }   
  if (empty_or_null(ver))
  {
    item = get_registry_value(handle:hklm, item:key + "\DisplayVersion");
    if (!empty_or_null(item))
    {
      match = eregmatch(string:item, pattern:"^(12\.[0-9.]+)(?:[^0-9|$])");
      if (!empty_or_null(match[1]))
        ver = match[1];
    }
  }
  name = "BlackBerry Enterprise Service";
}

RegCloseKey(handle:hklm);
NetUseDel();

# Generate report and save info in KB.
if (!empty_or_null(name) && !empty_or_null(ver) && !empty_or_null(path))
{
  set_kb_item(name:"BlackBerry_ES/Product", value:name);
  set_kb_item(name:"BlackBerry_ES/Version", value:ver);
  set_kb_item(name:"BlackBerry_ES/Path",    value:path);
  if (attachserver) set_kb_item(name:"BlackBerry_ES/AttachmentServer", value:TRUE);

  register_install(
    app_name:"BlackBerry Enterprise Service",
    path:path,
    version:ver,
    extra:make_array("Product", name),
    cpe:"cpe:/a:blackberry:blackberry_enterprise_service");

  if (report_verbosity > 0)
  {
    report = '\n  Product : ' + name +
             '\n  Path    : ' + path +
             '\n  Version : ' + ver +
             '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else audit(AUDIT_NOT_INST, "BlackBerry Enterprise Service / BlackBerry Enterprise Server / BlackBerry Unite!");
