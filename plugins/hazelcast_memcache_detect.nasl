#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67023);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/06/28 18:48:35 $");

  script_name(english:"Hazelcast Memcached Interface Detection");
  script_summary(english:"Detects Hazelcast memcached interface");

  script_set_attribute(attribute:"synopsis", value:"The memcached interface for a data clustering service was detected.");
  script_set_attribute(
    attribute:"description",
    value:
"The memcached interface for Hazelcast, an open source data clustering
solution, was detected on the remote host."
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:hazelcast:hazelcast");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("hazelcast_detect.nasl");
  script_require_ports("Services/hazelcast");
  script_require_keys("hazelcast");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "Hazelcast Memcached Interface";

port = get_service(svc:"hazelcast", exit_on_fail:TRUE);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

send(socket:soc, data:'stats\r\n');
res = recv(socket:soc, min:20, length:1024);
close(soc);

if (
  !isnull(res) &&
   res =~ "STAT[ ]*(uptime|threads|waiting_requests|curr_connections|" +
                   "total_connections|bytes|cmd_get|cmd_set|cmd_detect|" +
                   "get_hits|get_misses)[ ]+[0-9]+"
)
{
  set_kb_item(name:'hazelcast/' + port + '/memcached', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
    '\nNessus was able to verify the Hazelcast memcached interface is enabled' +
    '\nby running the "stats" command. \n';

    if (report_verbosity > 1)
    {
      report += '\nResponse : \n\n' +
      crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
      chomp(res) + '\n' +
      crap(data:"-" , length:30) + " snip " + crap(data:"-", length:30) + '\n' ;
    }
    security_note(extra:report, port:port);
  }
  else security_note(port);
}
else audit(AUDIT_NOT_LISTEN, appname, port);
