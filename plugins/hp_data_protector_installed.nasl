#
# Josh Zlatin-Amishav (josh at ramat dot cc)
# GPLv2
#

# Changes by Tenable:
# 2016 May 17
#   Added banner string detection for new HP naming scheme (HPE - Hewlett Packard Enterprise).
#   Added optimization check to ensure port 5555 has not been previously identified as a different service.
#   Minor adjustments in the description block.
# 2016 June 21
#   Revamped versioning due to HPE no longer updating the INET version along with the other components.
# 2016 June 24
#   Reworked some logic to consider the service as known and register the version and build even
#     if we couldn't get the INET banner.
#   Checked for previously identified banner before attempting to connect again.
#   Fixed the unicode handling logic.

include("compat.inc");

if (description) {
  script_id(19601);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/08/22 20:52:04 $");

  script_name(english:"HP Data Protector Detection");
  script_summary(english:"Checks for Data Protector.");

  script_set_attribute(attribute:"synopsis", value:
"A backup service is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"HP Data Protector (formerly HP OpenView Storage Data Protector), a
data management solution that automates backup and recovery, is
running on the remote host.");
  # http://www8.hp.com/us/en/software-solutions/data-protector-backup-recovery-software/index.html?
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c6f6271b");
  script_set_attribute(attribute:"solution", value:
"If this service is not needed, disable it or filter incoming traffic
to this port.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:storage_data_protector");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:data_protector");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Josh Zlatin-Amishav");

  script_require_ports("Services/hp_openview_dataprotector", 5555);
  script_dependencies("hp_data_protector_module_versions.nbin");

  exit(0);
}

include ("global_settings.inc");
include ("misc_func.inc");

core_ver = NULL;
core_ver = get_kb_item("Services/data_protector/core/Version");

core_build = NULL;
core_build = get_kb_item("Services/data_protector/core/Build");

# HPE refers to the initial, unpatched release as "MR" for "major release".
if (isnull(core_build) || core_build == "MR")
  core_build = 0;

# get_service will return if either the service was identified via
#   find_service.nasl (Best) or the service is unknown and also open
port = get_service(svc:'hp_openview_dataprotector', default:5555, exit_on_fail:TRUE);
response = get_unknown_banner(port:port, dontfetch:TRUE);

# If the banner wasn't previously found or the service is unknown
#   then we will try to get the spontaneous banner again but with
#   a longer delay
if (!response)
{
  soc = open_sock_tcp(port);
  if (soc)
  {
    # Data Protector can take some time to return its header
    response = recv(socket:soc, length:4096, timeout:20);
    close(soc);
  }
}

# Strip null characters introduced by a unicode response
if ('\0' >< response)
{
  response = join(sep:'', split(response, sep:'\0', keep:FALSE));
}

inet_version = NULL;
inet_build = NULL;

if (response && (
    "HP OpenView Storage Data Protector" >< response ||
    "HP Data Protector"                  >< response ||
    "HPE Data Protector"                 >< response
    ))
{
  # Get the INET build and version details
  version = eregmatch(pattern:'data protector ([^:]+)', string:response, icase:TRUE);
  build = eregmatch(pattern:'internal build ([^,]+)', string:response, icase:TRUE);

  if (version && !isnull(version[1]))
    inet_version = version[1];

  if (build && !isnull(build[1]))
    inet_build = build[1];
}
# If the INET banner wasn't detected and we learned nothing about
#   the data protector core module then it probably isn't data protector
else if (!core_ver && (!core_build || core_build == 0))
{
  exit(0, "HP OpenView Data Protector wasn't detected on the remote host.");
}

report = "";
# HPE has stopped updating the INET component along with th rest components. The only true
# component we can trust is 'core', if we are able to get it. We are unable to get this value
# when the traffic is encrypted between the node and the Cell Manager.
if (core_ver)
{
  # Register the 'core' as the overall version for DP, rather than the INET version
  replace_kb_item (name:"Services/data_protector/version", value:core_ver);
  report += '\nVersion       : ' + core_ver;
}
else{
  report += 'Nessus was unable to determine the version of HPE Data\n' +
            'Protector that is installed.';
  replace_kb_item (name:"Services/data_protector/version", value:"unknown");
}

if (core_build && core_build != 0)
{
  replace_kb_item (name:"Services/data_protector/build", value:core_build);
  report += '\nBuild         : ' + core_build;
}
else if (inet_build)
{
  # Setting this in case it's used as a constraining KB item.
  replace_kb_item (name:"Services/data_protector/build", value:inet_build);
}

if (!isnull(inet_version))
  # record the 'inet' version, rather than use it as the DP version
  set_kb_item (name:"Services/data_protector/inet/version", value:inet_version);
  report += '\nINET Version  : ' + inet_version;

if (!isnull(inet_build))
  # record the 'inet' build, rather than use it as the DP build
  set_kb_item (name:"Services/data_protector/inet/build", value:inet_build);
  report += '\nINET Build    : ' + inet_build;

#In case find_service1.nasl missed it
if (service_is_unknown(port:port))
  register_service(port:port, proto:"hp_openview_dataprotector");

if (report)
{
  # clean up formatting
  report += '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
}
exit(0);

