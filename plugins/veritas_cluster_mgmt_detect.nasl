#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
 script_id(52504);
 script_version("$Revision: 1.3 $");
 script_cvs_date("$Date: 2014/08/09 00:11:25 $");

 script_name(english:"Veritas Cluster Management Console Detection");
 script_summary(english:"Looks for Veritas Management Console");

 script_set_attribute(attribute:"synopsis", value:"The remote host is running a cluster administration console.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Veritas Cluster Management Console.

Since overloading this web service may force a cluster switch, web
tests will be disabled on this port." );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Veritas_Cluster_Server");
 script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/business/cluster-server");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/02");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:veritas_cluster_server_management_console");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

 script_dependencie("httpver.nasl", "broken_web_server.nasl");
 script_require_ports("Services/www", 8443);

 exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default: 8443);

w = http_send_recv3(method:"GET", item:'/Home.do', port:port, exit_on_fail: 1);

if ( '<TITLE>Symantec Web Server' >< w[2] &&
     '>Veritas Cluster Management Console Web Console <' >< w[2])
{
  add_install(appname:'veritas_cluster_mgmt', dir:'/', port:port);
  declare_broken_web_server(port:port, reason:
'Veritas Cluster Management Console should not be overloaded.');
  security_note(port);
  exit(0);
}

exit(0, "Veritas Cluster Management Console was not detected on port "+port+".");
