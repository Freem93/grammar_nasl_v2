#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67024);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/06/28 18:48:35 $");

  script_name(english:"Hazelcast REST Interface Detection");
  script_summary(english:"Detects Hazelcast REST interface");

  script_set_attribute(attribute:"synopsis", value:"The REST interface for a data clustering service was detected.");
  script_set_attribute(
    attribute:"description",
    value:
"The REST interface for Hazelcast, an open source data clustering
solution, was detected on the remote host."
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:hazelcast:hazelcast");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 5701);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "Hazelcast REST Interface";

port = get_http_port(default:5701);

res = http_send_recv3(item:"/hazelcast/rest/cluster",
                      port:port,
                      method:"GET",
                      exit_on_fail:TRUE);

if (
  res[2] =~ "(Members|Cluster)[ ]*\[[^\]]+\][ ]*{" &&
  "Member" >< res[2] &&
  "ConnectionCount" >< res[2]
)
{
  set_kb_item(name:'hazelcast/' + port + '/rest', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
    '\nNessus was able to verify the Hazelcast REST interface is enabled by' +
    '\nvisiting the following URL : \n' +
    '\n  ' + build_url(qs:'/hazelcast/rest/cluster', port:port) + '\n';

    if (report_verbosity > 1)
    {
      report += '\nResponse : \n\n' +
      crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
      chomp(res[2]) + '\n' +
      crap(data:"-" , length:30) + " snip " + crap(data:"-", length:30) + '\n' ;
    }
    security_note(extra:report, port:port);
  }
  else security_note(port);
}
else audit(AUDIT_NOT_LISTEN, appname, port);
