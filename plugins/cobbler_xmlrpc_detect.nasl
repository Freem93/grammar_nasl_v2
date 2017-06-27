#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(59401);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");

  script_name(english:"Cobbler Linux Installation Server Detection");
  script_summary(english:"Detects Cobbler xmlrpc API Interface");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is running a Linux installation and update server."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running Cobbler, a Linux installation and update
server."
  );
  script_set_attribute(attribute:"see_also", value:"http://cobbler.github.io/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:michael_dehaan:cobbler");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencie("cobbler_admin_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/cobbler_web_admin");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "Cobbler";

port = get_http_port(default:80);

# Admin interface is installed with xmlrpc API
install = get_install_from_kb(appname:'cobbler_web_admin', port:port, exit_on_fail:TRUE);

kb_base = "www/" + port + "/cobbler/xmlrpc/";

post_data = 
  "<?xml version='1.0'?>" + '\n' +
  "<methodCall>" + '\n' + 
  "<methodName>extended_version</methodName>" + '\n' +
  "<params>" + '\n' +
  "</params>" + '\n' + 
  "</methodCall>" + '\r\n';

res = http_send_recv3(
  port: port, 
  method: "POST",
  item: "/cobbler_api",
  data: post_data,
  exit_on_fail:TRUE
);

if (
  'version_tuple' >< res[2] &&
  'methodResponse' >< res[2]
)
{
  set_kb_item(name:"www/cobbler/xmlrpc", value:TRUE);

  version = "unknown";
  #<name>version</name>
  #<value><string>2.2.2</string></value>
  item = eregmatch(pattern: "<name>version</name>[ \n\t]+<value><string>([0-9\.]+)</string>", string:res[2]);
  if (!isnull(item)) version = item[1];

  set_kb_item(name:kb_base+"Version", value:version);

  report = '\n' + "  Version : " + version + '\n';

  #<name>gitdate</name>
  #<value><string>Tue Dec 6 19:15:18 2011 -0600</string></value>
  item = eregmatch(pattern: "<name>gitdate</name>[ \n\t]+<value><string>([^<]+)</string>", string:res[2]);
  
  if (!isnull(item))
  {
    report += "  Git Date : " + item[1] + '\n';  
    set_kb_item(name: kb_base + "GitDate", value: item[1]);
  }

  #<name>gitstamp</name>
  #<value><string>d64ed4d</string></value>
  item = eregmatch(pattern: "<name>gitstamp</name>[ \n\t]+<value><string>([^<]+)</string>", string:res[2]);
  
  if (!isnull(item))
  {
    report += "  Git Stamp : " + item[1] + '\n';  
    set_kb_item(name: kb_base + "GitStamp", value: item[1]);
  }

  if (report_verbosity > 0) security_note(port:port, extra:report);
  else security_note(port);
  exit(0);
}
else audit(AUDIT_NOT_DETECT, appname, port);
