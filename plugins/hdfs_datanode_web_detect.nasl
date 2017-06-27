#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50307);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/08/09 00:11:22 $");

  script_name(english:"Apache Hadoop HDFS DataNode Web Detection");
  script_summary(english:"Checks for the DataNode web interface");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The web interface of a node in a distributed file system was detected
on the remote host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The web interface for a DataNode was detected on the remote host.
A DataNode manages the storage attached to a node in a Hadoop
Distributed File System (HDFS) cluster."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?090ac656");
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
  script_require_ports("Services/www", 50075);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:50075);
installs = NULL;

# AFAICT this always comes bundled with Jetty and is served
# out of the web root
dir = '';
page = '/browseDirectory.jsp?dir=/';
url = dir + page;

res = http_send_recv3(method:'GET', item:url, port:port, exit_on_fail:TRUE);

if (
  '<title>HDFS:/</title>' >!< res[2] ||
  ('<a href=\'http://hadoop.apache.org/core\'>Hadoop</a>' >!< res[2] &&  #  < 0.20.203.0
   '<a href=\'http://hadoop.apache.org/\'>Apache Hadoop</a>' >!< res[2]) # >= 0.20.203.0
) exit(0, 'A DataNode interface wasn\'t detected on port '+port+'.');

# try to get the version if possible (looks like it first appeared in 0.20.203.0
match = eregmatch(string:res[2], pattern:'Hadoop</a> release ([0-9.]+)');
if (isnull(match))
  ver = NULL;
else
  ver = match[1];

installs = add_install(
  installs:installs,
  dir:dir,
  ver:ver,
  appname:'hdfs_datanode',
  port:port
);

if (report_verbosity > 0)
{
  report = get_install_report(
    display_name:'HDFS DataNode',
    item:page,
    installs:installs,
    port:port
  );
  security_note(port:port, extra:report);
}
else security_note(port);

