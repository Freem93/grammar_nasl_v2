#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58620);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/12 02:12:33 $");

  script_name(english:"Cisco WebEx ARF/WRF Player Installed");
  script_summary(english:"Checks registry/filesystem for ARF/WRF Players");

  script_set_attribute(attribute:"synopsis", value:"A video player is installed on the remote Windows host.");
  script_set_attribute(
    attribute:"description",
    value:
"Cisco WebEx ARF and/or WRF Player is/are installed on the remote
host.  ARF Player is used to watch recordings downloaded from WebEx.
WRF Player is used to watch self-created WebEx recordings."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.webex.com/play-webex-recording.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:webex");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("audit.inc");
include("install_func.inc");

registry_init();
handle = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\WebEx\Uninstall";
names = make_list('NBRPath', 'RecordPlaybackPath');
paths = get_values_from_key(handle:handle, key:key, entries:names);
RegCloseKey(handle:handle);

if (isnull(paths))
{
  close_registry();
  audit(AUDIT_NOT_INST, 'WebEx ARF/WRF Player');
}
else
  close_registry(close:FALSE);

installs = make_array();

foreach name (keys(paths))
{
  # the value pulled from the registry should be the absolute pathname of an exe file
  path = paths[name];
  ver = hotfix_get_fversion(path:path);

  # all we need is evidence that the file exists
  if (ver['error'] == HCF_OK || ver['error'] == HCF_NOVER)
  {
    # extract the directory from the pathname
    parts = split(path, sep:"\", keep:FALSE);
    dir = '';
    for (i = 0; i < max_index(parts) - 1; i++)
      dir += parts[i] + "\";

    if (name == 'NBRPath')
      installs['ARF Player'] = dir;
    else if (name == 'RecordPlaybackPath')
      installs['WRF Player'] = dir;
  }
}

hotfix_check_fversion_end();

if (max_index(keys(installs)) == 0)
  audit(AUDIT_UNINST, 'WebEx ARF/WRF Player');

port = kb_smb_transport();
report = '';

foreach product (keys(installs))
{
  path = installs[product];
  set_kb_item(name:'SMB/' + product + '/path', value:path);

  register_install(
    app_name:'WebEx ARF/WRF Player',
    path:path,
    cpe:"cpe:/a:cisco:webex");

  report +=
    '\n  Product : ' + product +
    '\n  Path    : ' + path + '\n';
}

if (report_verbosity > 0)
  security_note(port:port, extra:report);
else
  security_note(port);
