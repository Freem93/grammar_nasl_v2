#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42878);
  script_version("$Revision: 1.10 $");
 script_cvs_date("$Date: 2016/05/04 18:02:14 $");

  script_cve_id("CVE-2009-4060");
  script_bugtraq_id(37065);
  script_osvdb_id(60306);
  script_xref(name:"Secunia", value:"37402");

  script_name(english:"CubeCart includes/content/viewProd.inc.php productId Parameter SQL Injection");
  script_summary(english:"Attempts a SQL injection attack");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A PHP application hosted on the remote web server has a SQL injection
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of CubeCart running on the remote host has a SQL
injection vulnerability.  Input to the 'productId' parameter of is not
properly sanitized in 'includes/content/viewProd.inc.php' before it is
used in database queries.

Regardless of PHP's 'magic_quotes_gpc' setting, a remote attacker
could exploit this to execute arbitrary queries, which could, in turn
be used to take control of the database or mount further attacks."
  );
  script_set_attribute(attribute:"see_also", value:"http://forums.cubecart.com/index.php?showtopic=39900");
  script_set_attribute(attribute:"solution", value:"Upgrade to CubeCart 4.3.7 or apply the vendor's patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(89);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cubecart:cubecart");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("cubecart_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/cubecart");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80);

install = get_install_from_kb(appname:'cubecart', port:port);
if (isnull(install)) exit(0, "CubeCart wasn't detected on port " + port);

injection = '1+AND+1=0+UNION+SELECT+99887766';
url = install['dir'] + "/index.php?_a=viewProd&productId=" + injection;
res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

if (
  'MySQL Error Occurred' >< res[2] &&
  "WHERE `cart_order_id` = '99887766'" >< res[2] &&
  str_replace(string:injection, find:'+', replace:' ') >< res[2]
)
{
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);

  if (report_verbosity > 0)
  {
    header = "Nessus detected this issue based on the error message generated
by requesting the following URL";
    report = get_vuln_report(header:header, items:url, port:port);
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else
{
  cubecart_site = build_url(qs:install['dir'], port:port);
  exit(0, "The CubeCart site at " + cubecart_site + " is not affected.");
}

