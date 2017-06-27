#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66764);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/12 02:12:32 $");

  script_name(english:"Nitro Reader Installed");
  script_summary(english:"Checks for Nitro Reader");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host has a PDF reader installed.");
  script_set_attribute(attribute:"description", value:"Nitro Reader, a PDF reader, is installed on the remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"http://www.nitropdf.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nitropdf:nitro_pdf");
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

app = 'Nitro Reader';
port = kb_smb_transport();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
paths = make_list();
key = "SOFTWARE\Nitro\Reader";
subkeys = get_registry_subkeys(handle:hklm, key:key);
if (!isnull(subkeys))
{
  foreach subkey (subkeys)
  {
    if (subkey =~ '^[0-9\\.]+$')
    {
      path = get_registry_value(handle:hklm, item:key + '\\' + subkey + "\NitroPDFCreator\App Dir");
      if (!isnull(path)) paths = make_list(paths, path);
    }
  }
}
 # Older versions
key = "SOFTWARE\Nitro PDF\Reader";
subkeys = get_registry_subkeys(handle:hklm, key:key);
if (!isnull(subkeys))
{
  foreach subkey (subkeys)
  {
    if (subkey =~ '^[0-9\\.]+$')
    {
      path = get_registry_value(handle:hklm, item:key + '\\' + subkey + "\NitroPDFCreator\App Dir");
      if (!isnull(path)) paths = make_list(paths, path);
    }
  }
}
RegCloseKey(handle:hklm);

if (max_index(paths) == 0)
{
  close_registry();
  audit(AUDIT_NOT_INST, 'Nitro Reader');
}
close_registry(close:FALSE);

foreach path (list_uniq(paths))
{
  exe = path + 'NitroPDFReader.exe';

  ver = hotfix_get_fversion(path:exe);
  if (ver['error'] != HCF_OK) continue;

  version = join(ver['value'], sep:'.');

  path_parts = split(exe, sep:'\\', keep:TRUE);
  path = '';
  for (i = 0; i < max_index(path_parts) - 1; i++)
    path += path_parts[i];

  installs++;
  set_kb_item(name:'SMB/Nitro Reader/' + version + '/Path', value:path);

  register_install(
    app_name:'Nitro Reader',
    path:path,
    version:version,
    cpe:"cpe:/a:nitropdf:nitro_pdf");

  report +=
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';
}
hotfix_check_fversion_end();

if (report)
{
  set_kb_item(name:'SMB/Nitro Reader/installed', value:TRUE);
  if (report_verbosity > 0)
  {
    if (installs > 1) s = 's of Nitro Reader were found ';
    else s = ' of Nitro Reader was found ';
    report =
      '\n  The following install' + s + 'on the' +
      '\n  remote host :' +
      '\n' +
      report;
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else audit(AUDIT_UNINST, 'Nitro Reader');
