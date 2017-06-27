#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66896);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/07/12 02:12:33 $");

  script_name(english:"VMware vCenter Chargeback Manager Installed");
  script_summary(english:"Checks for VMware vCenter Chargeback Manager");

  script_set_attribute(attribute:"synopsis", value:"A cost reporting application is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"VMware vCenter Chargeback Manager, a cost reporting application, is
installed on the remote Windows host.");
  # https://www.vmware.com/products/it-business-management/vcenter-chargeback/overview.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?66849826");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/14");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_chargeback_manager");
  script_set_attribute(attribute:"plugin_type", value:"local");
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

app = 'VMware vCenter Chargeback Manager';
name   = kb_smb_name();
port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\VMware, Inc.\VMware vCenter Chargeback\Uninstall\InstallLocation";
path = get_registry_value(handle:hklm, item:key);
RegCloseKey(handle:hklm);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}
close_registry(close:FALSE);

share = hotfix_path2share(path:path);
config = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\config.xml", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

fh = CreateFile(
  file:config,
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
if (isnull(fsize)) fsize = 10240;
off = 0;
pat = '<Version>';
while (off <= fsize)
{
  data = ReadFile(handle:fh, length:10240, offset:off);
  if (strlen(data) == 0) break;

  if (pat >< data)
  {
    version = strstr(data, pat) - '<Version>';
    version = version - strstr(data, '</Version>');
    break;
  }
  off += 10240;
}

CloseFile(handle:fh);
NetUseDel();
if (isnull(version) || version !~ '^[0-9\\.]+$')
  audit(AUDIT_VER_FAIL, ((share - '$') + ':' + config));

set_kb_item(name:'SMB/'+app+'/Path', value:path);
set_kb_item(name:'SMB/'+app+'/Version', value:version);

register_install(
  app_name:app,
  path:path,
  version:version,
  cpe:"cpe:/a:vmware:vcenter_chargeback_manager");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
