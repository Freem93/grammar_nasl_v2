#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64558);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/07/12 02:12:33 $");

  script_name(english:"VMware vSphere Client Installed");
  script_summary(english:"Checks for VMware vSphere Client.");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host has a virtualization client installed.");
  script_set_attribute(attribute:"description", value:
"VMware vSphere Client, a client application for connecting to VMware
vSphere Server, is installed on the remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/support/product-support/vsphere/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/11");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vsphere_client");
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

  for (i=0; i<l; i++)
    res += str[i] + null;

  return res;
}

app = 'VMware vSphere Client';
name   = kb_smb_name();
port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\VMware, Inc.\VMware Virtual Infrastructure Client\VIClientRootPath";
path = get_registry_value(handle:hklm, item:key);

if (isnull(path))
{
  RegCloseKey(handle:hklm);
  close_registry();
  audit(AUDIT_NOT_INST, app);
}

paths = make_array();
# Determine the major versions that are installed
key = "SOFTWARE\VMware, Inc.\VMware Virtual Infrastructure Client";
subkeys = get_registry_subkeys(handle:hklm, key:key);
foreach subkey (subkeys)
{
  if (subkey =~ '^[0-9\\.]+$')
  {
    paths[subkey] = hotfix_append_path(path:path, value:subkey);
  }
}
RegCloseKey(handle:hklm);

if (max_index(keys(paths)) == 0)
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}
close_registry(close:FALSE);

share = hotfix_path2share(path:path);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

pat1 = 'vSphere Client';
pat2 = 'VMware Infrastructure Client';
installs = make_array();
foreach ver (keys(paths))
{
  version = '';
  build = '';
  data = '';
  off = 0;
  path = paths[ver];
  dll = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\VIClient.dll", string:path);

  fh = CreateFile(
    file:dll,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  if (isnull(fh))
    continue;

  fsize = GetFileSize(handle:fh);
  if (!isnull(fsize))
  {
    while (off <= fsize)
    {
      pat = '';
      content = ReadFile(handle:fh, length:10240, offset:off);
      if (strlen(content) == 0) break;

      if (mk_unicode(str:'vSphere Client ' + ver) >< content && mk_unicode(str:'build') >< content)
        pat = pat1;
      else if (mk_unicode(str:'VMware Infrastructure Client ' + ver) >< content && mk_unicode(str:'build') >< content)
        pat = pat2;

      if (pat)
      {
        # Parse out the version info
        content = strstr(content, mk_unicode(str:pat + ' ' + ver));
        idx_end = stridx(content, mk_unicode(str:'usage:'));
        content = substr(content, 0, idx_end);

        # Remove unicode separators
        for (i=0; i < strlen(content); i += 2)
          data += content[i];

        pat = pat + ' ([0-9\\.]+), build ([0-9]+)';
        matches = eregmatch(pattern:pat, string:data);
        if (!isnull(matches))
        {
          version = matches[1];
          build = matches[2];
          break;
        }
      }
      off += 10240;
    }
    if (version && build) installs[path] = version + ' build ' + build;
    CloseFile(handle:fh);
  }
}
close_registry();

if (max_index(keys(installs)) == 0)
{
  audit(AUDIT_UNINST, app);
}

set_kb_item(name:'SMB/'+app+'/Installed', value:TRUE);
report = '';
foreach install (sort(keys(installs)))
{
  set_kb_item(name:'SMB/'+app+'/'+installs[install]+'/Path', value:install);

  register_install(
    app_name:app,
    path:install,
    cpe:"cpe:/a:vmware:vsphere_client");

  report +=
    '\n  Path    : ' + install +
    '\n  Version : ' + installs[install] + '\n';
}
if (report_verbosity > 0)
{
  security_note(port:port, extra:report);
}
else security_note(port);
