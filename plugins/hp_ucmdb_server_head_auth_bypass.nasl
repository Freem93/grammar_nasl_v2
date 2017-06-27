#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81917);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/20 14:03:00 $");

  script_cve_id("CVE-2014-7883");
  script_bugtraq_id(72432);
  script_osvdb_id(117918);
  script_xref(name:"EDB-ID", value:"35982");

  script_name(english:"HP Universal Configuration Management Database Server Authentication Bypass");
  script_summary(english:"Checks the UCMDB Server for HTTP HEAD authentication bypass.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an authentication bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of HP Universal Configuration Management Database Server
running on the remote web server is affected by an authentication
bypass vulnerability due to the JMX-Console component performing
access control only for GET and POST methods. A remote attacker, using
the HTTP HEAD method, can bypass authentication to add a new
administrator user to the system, allowing full access.");
  # http://packetstormsecurity.com/files/130221/Hewlett-Packard-UCMDB-10.10-JMX-Console-Authentication-Bypass.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7cbe916d");
  script_set_attribute(attribute:"solution", value:"Contact the vendor.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:universal_configuration_management_database");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_ucmdb_server_detect.nbin");
  script_require_keys("installed_sw/HP Universal Configuration Management Database Server");
  script_require_ports("Services/www", 8080, 8443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("http.inc");

app_name = "HP Universal Configuration Management Database Server";

get_install_count(app_name:app_name, exit_if_zero:TRUE);

port = get_http_port(default:8080);

install = get_single_install(app_name:app_name, port:port);

url = build_url(port:port, qs:install['url']);

item = "/jmx-console/HtmlAdaptor?action=invokeOpByName&name=UCMDB:service=Authorization+Services&methodName=getUsers&arg0=1";

reply_GET = http_send_recv3(item:item, port:port, method:'GET', exit_on_fail:TRUE);
request_GET = http_last_sent_request();
if (isnull(reply_GET) || isnull(reply_GET[0]) || reply_GET[0] !~ "^HTTP/.* 401 ")
  exit(1, 'Nessus was unable to determine if the remote host is vulnerable since' + '\n' +
          'it received an unexpected non-401 response to an HTTP GET request.');

reply_HEAD = http_send_recv3(item:item, port:port, method:'HEAD', exit_on_fail:TRUE);
request_HEAD = http_last_sent_request();
if (isnull(reply_HEAD) || isnull(reply_HEAD[0]) || reply_HEAD[0] !~ "^HTTP/.* 200 ")
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url);

security_report_v4(
  port     : port,
  severity : SECURITY_HOLE,
  request  : make_list(request_HEAD),
  output   : chomp(reply_HEAD[0] + reply_HEAD[1]),
  generic  : TRUE
);
exit(0);
