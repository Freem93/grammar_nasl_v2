#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70069);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/20 14:29:55 $");

  script_name(english:"IBM WebSphere Service Registry and Repository Installed");
  script_summary(english:"Checks for IBM WebSphere Service Registry and Repository");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a software life cycle management
application installed.");
  script_set_attribute(attribute:"description", value:
"IBM WebSphere Service Registry and Repository, a software life cycle
management application, is installed on the remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"http://www-03.ibm.com/software/products/us/en/wsrr/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_service_registry_and_repository");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("smb_reg_query.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("install_func.inc");

name   = kb_smb_name();
port   = kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

get_kb_item_or_exit("SMB/Registry/Enumerated");


# Find out where the Installation Manager is saving installation information
app = 'IBM WebSphere Service Registry and Repository';

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE);
key = "SOFTWARE\IBM\Installation Manager\appDataLocation";
appdatapath = get_registry_value(handle:hklm, item:key);
RegCloseKey(handle:hklm);

if (isnull(appdatapath))
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}

# Look for the path in the installRegistry.xml file
share = hotfix_path2share(path:appdatapath);
xml = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\installRegistry.xml", string:appdatapath);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  close_registry();
  audit(AUDIT_SHARE_FAIL, share);
}

fh = CreateFile(
  file:xml,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

if (isnull(fh))
{
  close_registry();
  audit(AUDIT_UNINST, app);
}

wsrrpath = NULL;
fsize = GetFileSize(handle:fh);
if (fsize)
{
  off = 0;
  pattern = "<profile id='IBM WebSphere Application Server";
  while (off < fsize)
  {
    data = ReadFile(handle:fh, length:10240, offset:off);
    if (strlen(data) == 0) break;

    if (pattern >< data)
    {
      chunk = strstr(data, pattern) - pattern;
      chunk = strstr(chunk, "<property name='installLocation'") - "<property name='installLocation' value='";
      wsrrpath = chunk - strstr(chunk, "'/>");
      break;
    }
    off += 10240;
  }
}
CloseFile(handle:fh);
if (isnull(wsrrpath) || wsrrpath !~ '^[A-Za-z]:.*') exit(1, 'Failed to get the path of WebSphere Service Registry and Repository.');
wsrrshare = hotfix_path2share(path:wsrrpath);

# If the app is on another share, connect to that one
if (wsrrshare != share)
{
  NetUseDel(close:FALSE);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:wsrrshare);
  if (rc != 1)
  {
    close_registry();
    audit(AUDIT_SHARE_FAIL, wsrrshare);
  }
  if (rc != 1)
  {
    close_registry();
    audit(AUDIT_SHARE_FAIL, wsrrshare);
  }
}

wsrrpath = wsrrpath + "\WSRR";
properties = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\wsrrversion.properties", string:wsrrpath);;
fh = CreateFile(
  file:properties,
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
if (fsize)
{
  off = 0;
  while (off < fsize)
  {
    data = ReadFile(handle:fh, length:10240, offset:off);
    if (strlen(data) == 0) break;

    if ('version=' >< data)
    {
      chunk = strstr(data, 'version=') - 'version=';
      chunk = chunk - strstr(chunk, 'builddate');
      if ('_TRIAL' >< chunk) chunk = str_replace(string:chunk, find:'_TRIAL', replace:'');
      version = chomp(chunk);
      break;
    }
    off += 10240;
  }
}
CloseFile(handle:fh);
NetUseDel();

if (isnull(version))
  audit(AUDIT_VER_FAIL, wsrrpath + "\wsrrversion.properties");

register_install(
  app_name:app,
  path:wsrrpath,
  version:version,
  cpe:"cpe:/a:ibm:websphere_service_registry_and_repository");

if (report_verbosity > 0)
{
  report +=
    '\n  Path    : ' + wsrrpath +
    '\n  Version : ' + version + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
