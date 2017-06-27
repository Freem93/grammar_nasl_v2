#
# (C) Tenable Network Security. Inc.
#

include("compat.inc");

if (description)
{
  script_id(70120);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/12 02:12:32 $");

  script_name(english:"Juniper NetScreen VPN Client Detection");
  script_summary(english:"Detects Juniper NetScreen VPN Client");

  script_set_attribute(attribute:"synopsis", value:"The remote host has a VPN client installed.");
  script_set_attribute(attribute:"description", value:"The remote host has the Juniper NetScreen VPN Client installed.");
  # http://www.juniper.net/techpubs/en_US/release-independent/netscreen-remote/information-products/pathway-pages/netscreen-remote/product/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0fad7645");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:netscreen_remote_vpn_client");
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

app = 'Juniper NetScreen';

name   = kb_smb_name();
port   = kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

path = NULL;

display_names = get_kb_list('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');
if (!isnull(display_names))
{
  foreach key (keys(display_names))
  {
    display_name = display_names[key];
    if (display_name !~ 'NetScreen-Remote') continue;
    key = key - 'SMB/Registry/HKLM/' - 'DisplayName';
    key = str_replace(string:key, find:'/', replace:'\\');
    key += 'DisplayIcon';
    icon_path = get_registry_value(handle:hklm, item:key);
    if (!isnull(icon_path))
    {
      item = eregmatch(pattern:"^(.*)\\[^\\]+$", string:icon_path);
      path = item[1];
    }
    break;
  }
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}
close_registry(close:FALSE);

share = hotfix_path2share(path:path);
ini = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\version.ini", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

fh = CreateFile(
  file:ini,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

if (isnull(fh))
{
  NetUseDel();
  audit(AUDIT_UNINST, app);
}

version = NULL;
fsize = GetFileSize(handle:fh);
off = 0;
while (off <= fsize)
{
  data = ReadFile(handle:fh, length:10240, offset:off);
  if (strlen(data) == 0) break;

  if ("VersionString=" >< data)
  {
    item = eregmatch(string:data, pattern:"VersionString=([^\r\n]+)");
    if (!isnull(item)) version = item[1];
    break;
  }
  off += 10240;
}

CloseFile(handle:fh);
NetUseDel();

if (isnull(version)) audit(AUDIT_VER_FAIL, ((share - '$') + ':') + ini);

set_kb_item(name:'SMB/'+app+'/Path', value:path);
set_kb_item(name:'SMB/'+app+'/Version', value:version);
register_install(
  app_name:app,
  path:path,
  version:version,
  cpe:"cpe:/a:juniper:netscreen_remote_vpn_client");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
