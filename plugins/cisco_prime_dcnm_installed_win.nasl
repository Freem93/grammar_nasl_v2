#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67245);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/09/21 19:45:02 $");

  script_name(english:"Cisco Prime Data Center Network Manager Installed (Windows)");
  script_summary(english:"Looks for dcnm files");

  script_set_attribute(attribute:"synopsis", value:
"A network management system is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"Cisco Prime Data Center Network Manager (DCNM) is installed on the
remote host. DCNM is used to manage virtualized data centers.");
  # http://www.cisco.com/c/en/us/products/cloud-systems-management/prime-data-center-network-manager/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1553c88f");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_data_center_network_manager");
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

display_names = get_kb_list_or_exit('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');
uninstall_key = NULL;

# first check the Uninstall keys (stored in the KB) to see if looks like DCNM is installed
foreach key (keys(display_names))
{
  name = display_names[key];
  if (name != 'DCNM') continue;

  uninstall_key = key - 'SMB/Registry/HKLM/' - 'DisplayName';
  uninstall_key = str_replace(string:uninstall_key, find:'/', replace:"\");
}

if (isnull(uninstall_key))
  audit(AUDIT_NOT_INST, 'Cisco Prime DCNM');

# If it looks like it's installed, try to get the install path from the registry
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
path = get_registry_value(handle:hklm, item:uninstall_key + "UninstallString");
RegCloseKey(handle:hklm);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_UNINST, 'Cisco Prime DCNM');
}

# the path looks like "C:\Program Files\Cisco Systems\DCNM\Uninstall_DCNM\Uninstall DCNM.exe"
# the plugin needs to determine the path of the uninstall exe, and the path of the DCNM
# installation (one level up from the uninstall dir)
path = ereg_replace(string:path, pattern:'^"(.*)"$', replace:"\1"); # strip quotes if necessary
install_dir = NULL;
uninstall_dir = NULL;
parts = split(path, sep:"\", keep:TRUE);
for (i = 0; i < max_index(parts) - 2; i++)
  install_dir += parts[i];

uninstall_dir = install_dir + parts[i]; # the uninstall dir is one level deeper than the install dir

if (isnull(install_dir))
{
  close_registry();
  exit(1, 'Error parsing uninstall path : ' + path);
}

close_registry(close:FALSE);
share = hotfix_path2share(path:uninstall_dir);
port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

if (uninstall_dir[strlen(uninstall_dir) - 1] != "\") # add a trailing slash if necessary
  uninstall_dir += "\";
props_file = substr(uninstall_dir + 'installvariables.properties', 2); # strip out the leading drive name
fh = CreateFile(
  file:props_file,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

if (!isnull(fh))
{
  properties = NULL;
  length = GetFileSize(handle:fh);
  if (length > 100000) length = 100000;  # sanity check - max size of ~100k (it's about 33k in DCNM 6.2.1)
  while (strlen(properties) < length)
  {
    bytes_to_read = length - strlen(properties);
    if (bytes_to_read > 4096) bytes_to_read = 4096;

    bytes_read = ReadFile(handle:fh, offset:strlen(properties), length:bytes_to_read);
    if (strlen(bytes_read) == 0)
    {
      CloseFile(handle:fh);
      NetUseDel();
      exit(1, 'Function ReadFile() failed on ' + path + '.');
    }
    properties += bytes_read;
  }

  CloseFile(handle:fh);
}

NetUseDel();

match = eregmatch(string:properties, pattern:"PRODUCT_VERSION_NUMBER=([\d.]+)");
if (isnull(match)) audit(AUDIT_UNINST, 'Cisco Prime DCNM');
ver = match[1];

# the display version (e.g., 6.2(1) instead of 6.2.1.0), if present, can be
# found in a couple different places
match = eregmatch(string:properties, pattern:"DCNM_SPEC_VER=([\d.]+\([^)]+\))");
if (isnull(match))
  match = eregmatch(string:properties, pattern:"Data Center Network Manager\(DCNM\) ([\d.]+\([^)]+\))");
if (isnull(match))
  display_ver = ver;
else
  display_ver = match[1];

register_install(
  app_name:'Cisco Prime DCNM',
  path:install_dir,
  version:ver,
  display_version:display_ver,
  cpe:"cpe:/a:cisco:prime_data_center_network_manager"
);

report_installs(port:port);
