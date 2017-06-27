#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22231);
  script_version("$Revision: 1.24 $");

  script_cve_id("CVE-2006-4267", "CVE-2006-4268");
  script_bugtraq_id(19563);
  script_osvdb_id(27984, 27985, 27986, 27987);

  script_name(english:"CubeCart < 3.0.12 Multiple Vulnerabilities (SQLi, XSS)");
  script_summary(english:"Checks for a XSS flaw in CubeCart");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that suffers from
several flaws." );
 script_set_attribute(attribute:"description", value:
"The version of CubeCart installed on the remote host fails to properly
sanitize user-supplied input to several parameters and scripts before
using it in database queries and to generate dynamic web content.  An
unauthenticated attacker may be able to exploit these issues to
conduct SQL injection and cross-site scripting attacks against the
affected application." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2006/Aug/340" );
 script_set_attribute(attribute:"see_also", value:"http://www.cubecart.com/site/forums/index.php?showtopic=21247" );
 script_set_attribute(attribute:"solution", value:
"Either apply the patches referenced in the vendor advisory above or
upgrade to CubeCart version 3.0.12 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/08/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/08/17");
 script_cvs_date("$Date: 2017/05/11 13:46:37 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:cubecart:cubecart");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");
  script_dependencies("cubecart_detect.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/cubecart");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0, "The web server on port "+port+" does not support PHP");
if (get_kb_item("www/" + port + "/generic_xss")) exit(0, "The web server on port "+port+" is vulnerable to XSS");


# A simple alert.
xss = string('<script>alert("', SCRIPT_NAME, '")</script>');

# Test an install.
install = get_kb_item(string("www/", port, "/cubecart"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Try to exploit one of the XSS flaws as it works regardless of any PHP
  # settings and exists in several earlier versions.
  r = http_send_recv3(method:"GET", port: port, 
    item:string(dir, "/admin/login.php?", "email=", urlencode(str:xss)));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if we see our XSS.
  if (string("password has been emailed to ", xss) >< res)
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
