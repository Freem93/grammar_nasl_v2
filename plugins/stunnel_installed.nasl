#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65689);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/07/29 16:23:47 $");

  script_name(english:"stunnel Detection");
  script_summary(english:"Detects installation of stunnel.");

  script_set_attribute(attribute:"synopsis", value:
"An encryption wrapper application is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"stunnel, an encryption wrapper application that provides TLS
encryption functionality to existing clients and servers, is installed
on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www.stunnel.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:stunnel:stunnel");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

app = 'stunnel';
kb_base = "SMB/stunnel/";

name   = kb_smb_name();
port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\NSIS_stunnel\Install_Dir";
install_path = get_registry_value(handle:hklm, item:key);

if (isnull(install_path))
{
  key = "SYSTEM\CurrentControlSet\Services\stunnel\ImagePath";
  install_path = get_registry_value(handle:hklm, item:key);
}
RegCloseKey(handle:hklm);

if (isnull(install_path))
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}

close_registry(close:FALSE);

share = hotfix_path2share(path:install_path);
exe = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\stunnel.exe", string:install_path);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);

if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
# 5.x versions
if (isnull(fh))
{
  exe = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\bin\stunnel.exe", string:install_path);
  fh = CreateFile(
    file:exe,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
}
if (isnull(fh)) audit(AUDIT_UNINST, app);

fsize = GetFileSize(handle:fh);
off = 0;
version = NULL;

pat = "^([0-9]+\.[^ ]+) on [^ ]+ming.*$";
pat2 = "^([0-9]+\.[^ ]+) on [^ ]+ platform.*$";

while (fsize > 0 && off <= fsize && isnull(version))
{
  data = ReadFile(handle:fh, length:16384, offset:off);
  if (strlen(data) == 0) break;
  data = str_replace(find:raw_string(0), replace:"", string:data);

  while (strlen(data) && "stunnel " >< data)
  {
    data = strstr(data, "stunnel ") - "stunnel ";
    blob = data - strstr(data, '\n');

    # Older versions
    if (ereg(pattern:pat, string:blob))
      version = ereg_replace(pattern:pat, replace:"\1", string:blob);
    # Newer versions
    else
      if (ereg(pattern:pat2, string:blob))
        version = ereg_replace(pattern:pat2, replace:"\1", string:blob);

    if (version) break;
  }
  off += 16383;
}

CloseFile(handle:fh);
NetUseDel();

if (isnull(version)) version = "unknown";

register_install(
  app_name:app,
  path:install_path,
  version:version,
  cpe:"cpe:/a:stunnel:stunnel");

report_installs();
