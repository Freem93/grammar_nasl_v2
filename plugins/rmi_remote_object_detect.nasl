#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22363);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/04/20 21:37:48 $");

  script_name(english:"RMI Remote Object Detection");
  script_summary(english:"Detects RMI remote objects.");

  script_set_attribute(attribute:"synopsis", value:
"A Java service is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"One or more Java RMI remote objects are listening on the remote host. 
They may be used by Java applications to invoke methods on those
objects remotely.");
  # http://docs.oracle.com/javase/jndi/tutorial/objects/storing/remote.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bdbdbca1");
  script_set_attribute(attribute:"see_also", value:"http://docs.oracle.com/javase/1.5.0/docs/guide/rmi/spec/rmiTOC.html");
  # http://docs.oracle.com/javase/1.5.0/docs/guide/rmi/spec/rmi-protocol3.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb68319f");
  script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value: "2006/09/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("rmiregistry_detect.nasl");
  script_require_keys("Settings/ThoroughTests");

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("rmi.inc");

if (!thorough_tests) exit(0, "This script only runs in 'thorough mode'.");
get_kb_item_or_exit("global_settings/disable_service_discovery");
port = get_service(svc:"rmi_remote_object", ipproto:"tcp", exit_on_fail:TRUE);

# verify we can connect to this port using RMI
soc = rmi_connect(port:port);
close(soc);

report = '';
names = get_kb_list("Services/rmi/" + port + "/name");
if (!isnull(names))
{
  report = '\nThe following remote objects are supported:\n\n';
  host = get_host_name();
  foreach name (names) report += '  rmi://' + host + ':' + port + '/' + name + '\n';
}

security_report_v4(port:port, severity:SECURITY_NOTE, extra:report);
