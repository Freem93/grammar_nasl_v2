#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66908);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/07/12 02:12:34 $");

  script_name(english:"VMware vCenter Update Manager Detection (credentialed check)");
  script_summary(english:"Checks for vCenter Update Manager");

  script_set_attribute(attribute:"synopsis", value:
"A patch management application is installed on the remote Windows
host.");
  script_set_attribute(attribute:"description", value:
"VMware vCenter Update Manager (also known as vSphere Update Manager)
was detected on the remote Windows host.  This application is used to
manage patches on vSphere hosts.");
  # http://www.vmware.com/products/datacenter-virtualization/vsphere/update-manager.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3cb29e7a");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/17");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_update_manager");
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

function mk_unicode(str)
{
  local_var i, l, null, res;

  l = strlen(str);
  null = '\x00';
  res = "";

  for (i=0; i < l; i++)
    res += str[i] + null;

  return res;
}

get_kb_item_or_exit("SMB/Registry/Enumerated");

app = 'VMware vCenter Update Manager';
name   = kb_smb_name();
port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "Software\VMware, Inc.\VMware Update Manager\InstallPath";
path = get_registry_value(handle:hklm, item:key);
RegCloseKey(handle:hklm);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}
close_registry(close:FALSE);

share = hotfix_path2share(path:path);
exe = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\vmware-updatemgr.exe", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

if (isnull(fh))
{
  NetUseDel();
  audit(AUDIT_UNINST, app);
}

version = NULL;
build = NULL;
fsize = GetFileSize(handle:fh);
off = 0;
pat = 'FileVersion';
while (off <= fsize)
{
  data = ReadFile(handle:fh, length:10240, offset:off);
  if (strlen(data) == 0) break;

  if (mk_unicode(str:pat) >< data)
  {
    chunk = strstr(data, mk_unicode(str:pat)) - mk_unicode(str:pat);
    chunk = chunk - strstr(chunk, mk_unicode(str:'InternalName'));

    # Remove unicode separators
    for (i=4; i < strlen(chunk); i+= 2)
      version += chunk[i];

    pat = '([0-9\\.]+) build-([0-9]+)';
    matches = eregmatch(pattern:pat, string:version);
    if (!isnull(matches))
    {
      version = matches[1];
      build = matches[2];
      break;
    }
  }
  off += 10240;
}
CloseFile(handle:fh);
NetUseDel();

if (isnull(build) || isnull(version))
  exit(1, 'Failed to get the version from ' + path + "\vmware-updatemgr.exe.");

kb_base = 'SMB/' + app + '/';
set_kb_item(name:kb_base + 'Path', value:path);
set_kb_item(name:kb_base + 'Version', value:version);
set_kb_item(name:kb_base + 'Build', value:build);

register_install(
  app_name:app,
  path:path,
  version:version,
  extra:make_array('Build', build),
  cpe:"cpe:/a:vmware:vcenter_update_manager");

if (report_verbosity > 0)
{
  report +=
    '\n  Path    : ' + path +
    '\n  Version : ' + version +
    '\n  Build   : ' + build +
    '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
