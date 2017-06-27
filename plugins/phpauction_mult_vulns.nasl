#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(19227);
  script_version("$Revision: 1.18 $");

  script_cve_id(
    "CVE-2005-2252", 
    "CVE-2005-2253", 
    "CVE-2005-2254", 
    "CVE-2005-2255"
 );
  script_bugtraq_id(14184);
  script_osvdb_id(18997, 18998, 18999, 19000, 19001);

  name["english"] = "Phpauction <= 2.5 Multiple Vulnerabilities";
  script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Phpauction or one of its affiliate
versions, such as Web2035 Auction.  Phpauction is a web-based auction
system written in PHP. 

The version of Phpauction on the remote host suffers from multiple
flaws :

  - Remote Code Execution
    An attacker can control the 'lan' variable used to 
    include PHP code in the 'index.php' and 'admin/index.php'
    scripts, which may allow the viewing of arbitrary files 
    on the remote host and execution of arbitrary PHP code, 
    possibly even taken from third-party hosts.

  - Authentication Bypass
    By setting the cookie 'PHPAUCTION_RM_ID' to the id of an
    existing user, an attacker can bypass authentication.

  - SQL Injection
    The application does not properly sanitize user-supplied
    input to the 'category' parameter of the 'adsearch.php'
    script before using it in database queries.

  - Multiple Cross-Site Scripting Flaws
    The application fails to sanitize user-supplied input
    to several scripts before using it in dynamically-
    generated pages, which allows for cross-site scripting 
    attacks." );
 script_set_attribute(attribute:"see_also", value:"http://securitytracker.com/alerts/2005/Jul/1014423.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/20");
 script_cvs_date("$Date: 2014/05/21 17:27:25 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpauction:phpauction");
script_end_attributes();

 
  summary["english"] = "Checks for multiple vulnerabilities in Phpauction <= 2.5";
  script_summary(english:summary["english"]);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/" + port + "/generic_xss")) exit(0);


# A simple alert.
xss = '<script>alert("' + SCRIPT_NAME + '");</script>';
# nb: the url-encoded version is what we need to pass in.
exss = '%3Cscript%3Ealert("' + SCRIPT_NAME + '")%3B%3C%2Fscript%3E';
# There's a problem if we get our XSS back as part of a PHP error message.
pat = strcat("/includes/messages.", xss, ".inc.php): failed to open stream");

test_cgi_xss(port: port, dirs: cgi_dirs(), cgi: "/index.php",
  sql_injection: 1, high_risk: 1,
  pass_str: pat, qs: "lan="+exss);
