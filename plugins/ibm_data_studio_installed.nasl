#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65575);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/12 02:12:33 $");

  script_name(english:"IBM Data Studio Detection");
  script_summary(english:"Detects installs of IBM Data Studio");

  script_set_attribute(attribute:"synopsis", value:"The remote host has a database development environment installed.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has IBM Data Studio installed, a database development
environment."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/developerworks/downloads/im/data/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:data_studio");
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
include("torture_cgi_func.inc");
include("install_func.inc");

app = 'IBM Data Studio';
kb_base = "SMB/ibm_data_studio/";

name   = kb_smb_name();
port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\' +
      'IM-IBM Data Studio\\UninstallString';
uninstall_path = get_registry_value(handle:hklm, item:key);

RegCloseKey(handle:hklm);

if (isnull(uninstall_path))
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}

close_registry(close:FALSE);

item = eregmatch(pattern:'-input\\s*\"(.+\\\\)uninstall\\\\', string:uninstall_path);
if (isnull(item)) exit(1, "Unable to parse uninstall path string.");

path = item[1];

share = hotfix_path2share(path:path);
notice_file = ereg_replace(pattern:'^[A-Za-z]:(.*)',
              replace:"\1dsmini\licenses\notices", string:path);
notice_file1 = ereg_replace(pattern:'^[A-Za-z]:(.*)',
               replace:"\1dsmini\licenses\notices.html", string:path);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);

if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

verified = FALSE;

# try and extract version information from notice file
foreach file (make_list(notice_file, notice_file1))
{
  fh = CreateFile(
    file:file,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  if (isnull(fh)) continue;

  verified = TRUE;

  fsize = GetFileSize(handle:fh);
  version = 'unknown';

  # version info is at top of file
  if (fsize > 1024) fsize = 1024;

  if (fsize)
  {
    data = ReadFile(handle:fh, length:fsize, offset:0);
    data = tolower(utf16_to_ascii(s:data));
    if (data && 'ibm data studio' >< data)
    {
      item = eregmatch(pattern:'ibm data studio client v([0-9.]+)',
                       string:data);
      if (!isnull(item)) version = item[1];

      # detect "full" client and other variants
      item = eregmatch(pattern:'ibm data studio [^\n]+ v([0-9.]+)',
                       string:data);
      if (!isnull(item)) version = item[1];
    }
  }
  CloseFile(handle:fh);
  break;
}
NetUseDel();

if (!verified) audit(AUDIT_UNINST, app);

set_kb_item(name:kb_base + 'Path', value:path);
set_kb_item(name:kb_base + 'Version', value:version);

register_install(
  app_name:app,
  path:path,
  version:version,
  cpe:"cpe:/a:ibm:data_studio");

if (report_verbosity > 0)
{
  report = '\n  Path    : ' + path +
           '\n  Version : ' + version + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
