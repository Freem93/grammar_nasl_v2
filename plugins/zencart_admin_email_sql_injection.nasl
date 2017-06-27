#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20254);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2012/11/16 02:30:39 $");

  script_cve_id("CVE-2005-3996");
  script_bugtraq_id(15690);
  script_osvdb_id(21411);

  script_name(english:"Zen Cart password_forgotten.php admin_email Parameter SQL Injection");
  script_summary(english:"Checks for admin_email parameter SQL injection vulnerability in Zen Cart");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server has a PHP application that is affected by a SQL
injection flaw.");
  script_set_attribute(attribute:"description", value:
"The installed version of Zen Cart does not validate input to the
'admin_email' parameter of the 'admin/password_forgotten.php' script
before using it in a database query.  Regardless of PHP's
'magic_quotes_gpc' setting, an attacker can leverage this issue to
manipulate SQL queries, possibly gaining the ability to execute
arbitrary PHP code on the remote host subject to the privileges of the
web server user id.");
  script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/zencart_126d_xpl.html");
  script_set_attribute(attribute:"solution", value:
"Configure the database so it can not write to files in the web server's
document directory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/12/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zen-cart:zen_cart");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");

  script_dependencies("zencart_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/zencart");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0, "The web server on port "+port+" does not support PHP");


# Test an install.
install = get_kb_item(string("www/", port, "/zencart"));
if (isnull(install)) exit(0, "Zencart was not detected on port "+port);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  url = string(dir, "/admin/password_forgotten.php");

  # Make sure the affected script exists.
  r = http_send_recv3(method: "GET", port:port, item: url);
  if (isnull(r)) exit(0);

  # If it does...
  if ('name="admin_email" value="" />' >< r[2]) {
    # Try to exploit the flaw to get a syntax error.
    postdata = string(
      "admin_email='", SCRIPT_NAME, "&",
      "submit=resend"
    );
    
    req = string(
      "POST ", url, " HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    r = http_send_recv3(method: "POST", port:port, item: url, data: postdata, add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"), version: 11);
    if (isnull(r)) exit(0);

    res = strcat(r[0], r[1], '\r\n', r[2]);

    # There's a problem if we get a syntax error involving our script name.
    if (egrep(pattern:string("an error in your SQL syntax.+ near '", SCRIPT_NAME), string:res)) {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    }
  }
}
