#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50305);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/08/09 00:11:22 $");

  script_name(english:"Apache Hadoop MapReduce TaskTracker Web Interface");
  script_summary(english:"Looks for the TaskTracker status page");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The web interface for a distributed computing system was detected on
the remote host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The web interface for Hadoop MapReduce TaskTracker was detected on the
remote host.  This interface can be used to monitor MapReduce tasks
submitted to this node."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6c6d19de");
  script_set_attribute(attribute:"solution", value:"Limit incoming traffic to this port if desired.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:hadoop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 50060);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:50060);
pattern = 'Version:</b> *([0-9.]+)';
installs = NULL;

# AFAICT this always comes bundled with Jetty and is served
# out of the web root
dir = '';
page = '/tasktracker.jsp';
url = dir + page;

res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

if ('Task Tracker Status</title>' >!< res[2])
  exit(0, 'A MapReduce TaskTracker interface wasn\'t detected on port '+port+'.');

ver = NULL;
match = eregmatch(string:res[2], pattern:pattern, icase:TRUE);
if (match) ver = match[1];

installs = add_install(
  installs:installs,
  dir:dir,
  ver:ver,
  appname:'hadoop_mapreduce_tasktracker',
  port:port
);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'Hadoop MapReduce TaskTracker',
    installs:installs,
    port:port
  );
  security_note(port:port, extra:report);
}
else security_note(port);

