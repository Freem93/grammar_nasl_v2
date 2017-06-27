#TRUSTED 0a2924226170ba8dbf1d25bad02c5f40b6664827689e875e73fc4e25fecb266d9e70c50a462817a56db82297b79678c4aaa49c3cb28799540e7c8b9fb2be6adf79cca674f322c060fa042107bae9ec525db2d6f241276a4916c1e6b43ea0dcf4adbed4a71c86190e8498f7557b16aa67d6feb96b72c1ad48f324fe5e7bcae875d44a083d67702165f920cffbf2e1a484c3ed1079c91c36868fdb3e782b641b85cba018cef88a8974477c04c9360423db54e7521ccabd77b6b5db65b6ca987ba11c687086f836bac4be67aa38585c6d5211608a8fbf49cb7ddf1d8f4fd424b2cabb2921b4bd1b762078d637bbdfe5526e754166144903d6ceec78d9b6e6fef2174746f76e0ed5e5e14f3c06defdc86fc1c630d4dedbd8c96738c01626e77b49a1e1e8fc31de89964b501353cb4be3ad67a13b7aa87fb2164b2f291d0c76dff5d6a96c64363d3db4f9c962f68e72f1523d34c38895fde18b7156002f661550ddad8bbaa94d6e4f053bf101d005f83a37a47b142757e55b00299edc2560940fdeca1505a9f8b5715e60154b76eb04427c08807f549c761b1114a11b57526b32f19f88697472184687b73dbcd510b9376c6be50c12bea7711e2e6424e55a5e446a1ec3b3c1d45f59e2717c9e9c0fd7efceab4d6e3baacb13837f30549ee4e32a940136519e565b746166896d3b60a31ebf3d09b061db7586b362c1f0742c04a7c5d6
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69446);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/11");

  script_name(english:"ArcSight Logger Installed (Linux)");
  script_summary(english:"Looks for log files containing version information.");

  script_set_attribute(attribute:"synopsis", value:
"A log collection and management system is installed on the remote
Linux host.");
  script_set_attribute(attribute:"description", value:
"ArcSight Logger is installed on the remote host. ArcSight Logger is
used to collect and manage logs.");
  # http://www8.hp.com/ca/en/software-solutions/software.html?compURI=1314386#.Ug5u237YUzk
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84aa80ae");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:arcsight_logger");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("HostLevelChecks/proto", "Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("install_func.inc");

proto = get_kb_item_or_exit('HostLevelChecks/proto');
get_kb_item_or_exit("Host/local_checks_enabled");

# Do not run against Windows
# It's not supported
os = get_kb_item('Host/OS');
if (isnull(os) || 'Linux' >!< os)
  audit(AUDIT_OS_NOT, "a Linux OS");

if (proto == 'local')
  info_t = INFO_LOCAL;
else if (proto == 'ssh')
{
  info_t = INFO_SSH;
  ret = ssh_open_connection();
  if (!ret) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
}
else
  exit(0, 'This plugin only attempts to run commands locally or via SSH, and neither is available against the remote host.');

ver_ui_map = make_array(
  '5.3.1.0',      '5.3 SP1', # Less detail from install-log files
  '5.3.1.6838.0', '5.3 SP1'  # More detail from log files
);

default_as_logger_path = "/opt/current/arcsight/";
version = NULL;
appears_to_be_installed = FALSE;

# Use only default install location files for now
files_and_patterns = make_array(
  '/opt/UninstallerData/installvariables.properties',            '"PRODUCT_VERSION_NUMBER="',
  default_as_logger_path + 'logger/logs/logger_server.out.log', '"\\[INFO \\] Version "',
  default_as_logger_path + 'logger/logs/logger_server.log*',     '"\\[INFO \\]\\[Server\\]\\[go\\]\\[main\\] Version "',
  default_as_logger_path + 'logger/logs/logger_processor.log*',  '"\\[INFO \\]\\[LoggerProcessors\\]\\[go\\]\\[main\\] Version "',
  default_as_logger_path + 'logger/logs/logger_receiver.log*',   '"\\[INFO \\]\\[LoggerReceivers\\]\\[go\\]\\[main\\] Version "'
);

output = info_send_cmd(cmd:"test -d " + default_as_logger_path + " && echo OK");
if ( "OK" >!< output ) audit(AUDIT_NOT_INST, 'ArcSight Logger');

# Look into each potential data file on the target
foreach ver_file (keys(files_and_patterns))
{
  temp_version = "";

  # logger_server.out.log uses a text-based day-of-week and thus, skip sorting date
  # The other files use a fully number-based date and thus, look at them all and sort on date
  if (".out." >< ver_file)
    output = info_send_cmd(cmd:"grep -h " + files_and_patterns[ver_file]  + " " + ver_file + " | tail -n 1");
  else
    output = info_send_cmd(cmd:"grep -h " + files_and_patterns[ver_file]  + " " + ver_file + " | sort | tail -n 1");

  res = egrep(string:output, pattern:str_replace(string:files_and_patterns[ver_file], find:'"', replace:""));

  if (!strlen(res))
    continue;
  else
    appears_to_be_installed = TRUE;

  res = chomp(res);

  if ("properties" >< ver_file)
    temp_version = res - "PRODUCT_VERSION_NUMBER=";
  else
  {
    matches = eregmatch(string:res, pattern:" Version ([0-9.]+)");
    if (!isnull(matches))
      temp_version = matches[1];
  }

  # Keep most detailed version number
  if (max_index(split(temp_version, sep:".")) > max_index(split(version, sep:".")))
    version = temp_version;
}

if (appears_to_be_installed && isnull(version))
  version = 'unknown';

if (!isnull(version))
{
  set_kb_item(name:'hp/arcsight_logger/path', value:default_as_logger_path);
  set_kb_item(name:'hp/arcsight_logger/ver', value:version);

  # If we have user-friendly version string, store it
  if (!isnull(ver_ui_map[version]))
  {
    display_version = ver_ui_map[version] + " (" + version + ")";
    set_kb_item(name:'hp/arcsight_logger/display_ver', value:display_version);
  }
  else display_version = version;

  register_install(
    app_name:'ArcSight Logger',
    path:default_as_logger_path,
    version:version,
    display_version:display_version,
    cpe:"cpe:/a:hp:arcsight_logger");

  if (report_verbosity > 0)
  {
    report =
      '\n  Path    : ' + default_as_logger_path +
      '\n  Version : ' + display_version + '\n';
    security_note(port:0, extra:report);
  }
  else security_note(0);
  exit(0);
}
audit(AUDIT_NOT_INST, 'ArcSight Logger');
