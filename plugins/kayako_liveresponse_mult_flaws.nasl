#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) 
{
  script_id(19335);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2012/12/04 23:10:47 $");

  script_cve_id(
    "CVE-2005-2460", 
    "CVE-2005-2461", 
    "CVE-2005-2462", 
    "CVE-2005-2463"
 );
  script_bugtraq_id(14425);
  script_osvdb_id(
    18395, 
    18396, 
    18397, 
    18398, 
    18399
 );

  script_name(english:"Kayako LiveResponse Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple input validation vulnerabilities in Kayako LiveResponse");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
variety of flaws.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Kayako LiveResponse, a web-based live
support system. 

The installed version of Kayako LiveResponse on the remote host fails
to sanitize user-supplied input to many parameters / scripts, which
makes the application vulnerable to SQL injection and cross-site
scripting attacks.  In addition, the application embeds passwords in
plaintext as part of GET requests and will reveal its installation
directory in response to direct calls to several scripts.");
   # http://web.archive.org/web/20080918071253/http://www.gulftech.org/?node=research&article_id=00092-07302005
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b34a9173");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/406914");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:kayako:liveresponse");
  script_end_attributes();
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:80, php:TRUE);
if ( get_kb_item("www/" + port + "/generic_xss") )
  exit(1, "The server listening on port "+port+" is affected by a generic cross-site-scripting vulnerability.");

# A simple alert.
xss = "<script>alert(document.cookie);</script>";

affected = test_cgi_xss(port: port, cgi: "/index.php", dirs: cgi_dirs(), sql_injection: 1,
 qs: strcat( "username=", urlencode(str:string('">', xss)), "&",
	     "password=", SCRIPT_NAME), 
 # There's a problem if we see our XSS as part of the LiveResponse 
 # login form.
  pass_str: strcat('input name=username type=text value="\">',xss) );

if (!affected)
  exit(0, "No affected URLs were found on port "+port+".");
