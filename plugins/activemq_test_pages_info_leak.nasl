#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45553);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/21 20:34:20 $");

  script_name(english:"Apache ActiveMQ Web Console Test Pages Information Disclosure");
  script_summary(english:"Checks if systemProperties.jsp is accessible.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is leaking information.");
  script_set_attribute(attribute:"description", value:
"The Apache ActiveMQ Web Console running on the remote host is leaking
information via its test pages. The ActiveMQ Web Console allows
unrestricted, unauthenticated access by default, and the test pages
are used for testing the environment and web framework.

One of the included test pages, 'systemProperties.jsp', displays
information about the ActiveMQ installation and the system it is
running on, which a remote attacker can use to mount further attacks.");
  script_set_attribute(attribute:"see_also", value:"http://activemq.apache.org/web-console.html");
  script_set_attribute(attribute:"solution", value:"Restrict access to the ActiveMQ Web Console.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:activemq");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("activemq_web_console_detect.nasl");
  script_require_keys("installed_sw/ActiveMQ");
  script_require_ports("Services/www", 8161);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = 'ActiveMQ';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8161);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

url = '/test/systemProperties.jsp';
res = http_send_recv3(method:"GET", item:dir+url, port:port, exit_on_fail:TRUE);

if ('Test Pages</title>' >< res[2] && 'java.class.version' >< res[2])
{
  # attempt to extract some information of interest
  info = '';
  props = make_array(
    'activemq.home', 'ActiveMQ path',
    'os.name', 'Operating system',
    'java.version','Java version',
    'os.arch', 'Architecture'
  );

  foreach prop (keys(props))
  {
    pattern = '<td class="label">'+prop+'</td>[ \\r\\n\\t]+<td>([^<]+)</td>';
    match = eregmatch(string:res[2], pattern:pattern);
    if (match) info += '  ' + props[prop] + ': ' + match[1] + '\n';
  }

  if (empty_or_null(info)) info = res[2];

  security_report_v4(
    port        : port,
    severity    : SECURITY_WARNING,
    generic     : TRUE,
    line_limit  : 5,
    request     : make_list(install_url + url),
    output      : info
  );
  exit(0);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

