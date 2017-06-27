#TRUSTED 1be45b152a788996508a25ce890656ce3e9e97ed30c387ca9b25c139a8dc00114ba819b5b7689da1dccb555be7ca628f91c64165b9816dc78af157fa9668363d8eb1a9dabd476d0d308642de347d02c9ecd35134b35db22dbfd590c1fd5457671b561303f51879457921a2f95777206919081bac61607f991ae8d1d7967f84354e587f182bb309a0a043e280948c5950b3a6711aee38e459dfc0e4de8987723b848b9e6e0b58489cef9b299a71271d15eb1720cbe8f6273954ad4624a1f53c8a6e9aa6b9d3a00f848522941339e7eb69511f7225615e1026a0d1f7161db2b33c252cafa3f240ea9af1ec4bd82a0a318622feac0841a0b03f71d8aa18fd316117ded31b1d5084e553d7bc4126d786a9510228a826baa05b710c9219c7b306e9a1b6eb5bafed5986cc0aba713dde20e62fb12c5a16bc7add7ad4c79ea6e96504c2079df628e6f11b9342d3540751a55487a9b3794629fde794b73d2896f9d21d250988f4464cffa7dfca72a99934a54fd91db5aabcd4cea57ba0d729bf8626abfd1b2359cbb2684231383aa2f52b53311f9bdb5be147acaeafb80bede38b946a97d691cc4197a7192702f9d3d6b9a68b49c0626e2a85ec83327597856c926dcb4ed7d32c589c8ce9af17762cb7b8190158bf07d7b491dea2790e9da4c7cf50eb2730dff048ba59c65e26e1d6cd8f430a307ceca1e92ec90eaa814faf267e692427
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69130);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/11");

  script_name(english:"Cisco Wireless Control System Installed (Linux)");
  script_summary(english:"Looks for WCS files");

  script_set_attribute(attribute:"synopsis", value:
"A wireless management application is installed on the remote Linux
host.");
  script_set_attribute(attribute:"description", value:
"Cisco Wireless Control System (WCS) is installed on the remote host.
WCS is used as the management component for Cisco Unified Wireless
Network.");
  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/ps6305/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:wireless_control_system_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("HostLevelChecks/proto");

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

if (proto == 'local')
  info_t = INFO_LOCAL;
else if (proto == 'ssh')
{
  info_t = INFO_SSH;
  ret = ssh_open_connection();
  if (!ret)
  {
    error = get_ssh_error();
    if (error)
      extra = ' (' + error + ')';
    else
      extra = '';
    exit(1, 'ssh_open_connection() failed' + extra + '.');
    audit(AUDIT_FN_FAIL, 'ssh_open_connection');
  }
}
else
  exit(0, 'This plugin only attempts to run commands locally or via SSH, and neither is available against the remote host.');

nmsadmin = info_send_cmd(cmd:'grep ^NMSADMIN= /etc/init.d/WCS*');
report = NULL;

foreach line (split(nmsadmin, sep:'\n', keep:FALSE))
{
  # examples:
  # NMSADMIN=/opt/WCS6.0.132.0/bin/nmsadmin.sh
  # NMSADMIN=/usr/local/wcs/bin/nmsadmin.sh
  match = eregmatch(string:line, pattern:"NMSADMIN=(.+)/bin/nmsadmin\.sh");
  if (isnull(match)) continue;

  # only assume that the install is valid if the plugin is able to get
  # its version number from a file under the installation root
  path = match[1];
  prop_file = path + '/webnms/classes/com/cisco/common/ha/config/ha.properties';
  prop_file = str_replace(string:prop_file, find:"'", replace:'\'"\'"\'');  # replace ' with '"'"' to prevent command injection
  cmd = 'grep ^version= ' + prop_file;
  ver_prop = info_send_cmd(cmd:cmd);

  # example:
  # version=6.0.132.0
  match = eregmatch(string:ver_prop, pattern:'^version=([0-9.]+)$');
  if (isnull(match)) continue;

  version = match[1];
  set_kb_item(name:'cisco_wcs/version', value:version);
  set_kb_item(name:'cisco_wcs/' + version + '/path', value:path);
  register_install(
    app_name:'Cisco WCS',
    path:path,
    version:version,
    cpe:"cpe:/a:cisco:wireless_control_system_software");
  report +=
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';
}

if (isnull(report))
  audit(AUDIT_NOT_INST, 'Cisco WCS');

if (report_verbosity > 0)
  security_note(port:0, extra:report);
else
  security_note(0);
