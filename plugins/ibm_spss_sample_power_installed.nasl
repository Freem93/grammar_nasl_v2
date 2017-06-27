#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66472);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/12 02:12:33 $");

  script_name(english:"IBM SPSS SamplePower Detection");
  script_summary(english:"Detects installs of IBM SPSS SamplePower");

  script_set_attribute(attribute:"synopsis", value:"The remote host has a statistical analysis program installed.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running IBM SPSS SamplePower, a statistical analysis
program."
  );
  script_set_attribute(attribute:"see_also", value:"http://www-03.ibm.com/software/products/us/en/spss-samplepower/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:spss_samplepower");
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

kb_base = 'SMB/ibm_spss_samplepower/';
app = 'IBM SPSS SamplePower';

name   = kb_smb_name();
port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

display_names = get_kb_list_or_exit('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

foreach key (keys(display_names))
{
  display_name = display_names[key];
  if ('SamplePower' >< display_name)
  {
    key = key - 'SMB/Registry/HKLM/' - 'DisplayName';
    key = str_replace(string:key, find:'/', replace:'\\');
    key += 'Readme';
    readme = get_registry_value(handle:hklm, item:key);
    break;
  }
}
if (isnull(readme))
{
  RegCloseKey(handle:hklm);
  close_registry();
  audit(AUDIT_NOT_INST, app);
}
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

item = eregmatch(pattern:"^([a-zA-Z]:.*\\)[^\\]*$", string: readme);
if (isnull(item)) exit(1, 'Error parsing path from \'' + key + '\'.');

path = item[1];
reportpath = path;

share = hotfix_path2share(path:path);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

path = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1", string:path);
version = NULL;
file = path + 'spssprod.inf';

fh = CreateFile(
  file:file,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (isnull(fh))
  audit(AUDIT_NOT_INST, app);

version = "unknown";

contents = ReadFile(handle:fh, offset:0, length:1024);
if (contents)
{
  item = eregmatch(pattern:"Version=[ ]*([^ \t\n\r]+)",
                   string:contents);
  if(!isnull(item) && !isnull(item[1]))
    version = item[1];

  CloseFile(handle:fh);
}
NetUseDel();

set_kb_item(name:kb_base + 'Path', value:reportpath);
set_kb_item(name:kb_base + 'Version', value:version);

register_install(
  app_name:app,
  path:reportpath,
  version:version,
  cpe:"cpe:/a:ibm:spss_samplepower");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + reportpath +
    '\n  Version : ' + version + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
