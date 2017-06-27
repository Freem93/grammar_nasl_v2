#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34108);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/05/04 18:02:24 $");

  script_cve_id("CVE-2008-6986");
  script_bugtraq_id(31023);
  script_osvdb_id(48347);

  script_name(english:"Zen Cart products_id[] Array SQL Injection");
  script_summary(english:"Tries to generate a SQL syntax error");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to a SQL
injection attack.");
  script_set_attribute(attribute:"description", value:
"The installed version of Zen Cart does not validate user-supplied input
to the 'products_id[]' parameter array of the 'index.php' script when
'action' is set to 'multiple_products_add_product' before using the keys
in a database query in the 'in_cart_mixed()' function in
'includes/classes/shopping_cart.php'.  Provided PHP's 'magic_quotes_gpc'
setting is off, an unauthenticated, remote attacker can leverage this
issue to manipulate SQL queries and, for example, uncover sensitive
information from the application's database or possibly execute
arbitrary PHP code. 

Note that there are also reportedly other SQL injection issues in this
version of Zen Cart, although Nessus has not tested for them
explicitly.");
   # http://web.archive.org/web/20080912045835/http://www.gulftech.org/?node=research&article_id=00129-09042008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?de36ae73");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/496032");
  script_set_attribute(attribute:"see_also", value:"http://www.zen-cart.com/forum/showthread.php?p=604473");
  script_set_attribute(attribute:"solution", value:
"Patch 'includes/classes/shopping_cart.php' as described in the vendor
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(89);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zen-cart:zen_cart");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("zencart_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0, "The web server on port "+port+" does not support PHP");


# Test an install.
install = get_kb_item(string("www/", port, "/zencart"));
if (isnull(install)) exit(0, "Zencart was not detected on port "+port);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit the flaw to generate a SQL syntax error.
  exploit = string("-99' ", SCRIPT_NAME);
  postdata = string("products_id[", urlencode(str:exploit), "]=1");
  url = string(dir, "/index.php?action=multiple_products_add_product");

  r = http_send_recv3(method: "POST", item: url, port: port,
   content_type: "application/x-www-form-urlencoded", data: postdata);
  if (isnull(r)) exit(0);

  if (
    "SQL syntax" >< r[2] &&
    string("where products_id='", exploit, "'") >< r[2]
  )
  {
    set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
    security_warning(port);
  }
}
