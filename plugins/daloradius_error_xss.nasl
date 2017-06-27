#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(43403);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2011/03/07 16:28:07 $");

  script_cve_id("CVE-2009-4347");
  script_bugtraq_id(41807);
  script_xref(name:"EDB-ID", value:"10460");
  script_xref(name:"OSVDB", value:"61055");

  script_name(english:"daloRADIUS login.php error Parameter XSS");
  script_summary(english:"Tries to inject script code through 'error' parameter");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a PHP script that is prone to a cross-
site scripting attack."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote web server hosts daloRADIUS, an advanced RADIUS web
management application. 

The installed version of daloRADIUS server fails to sanitize user-
supplied input to the 'error' parameter of the 'login.php' script
before using it to generate dynamic HTML output. 

An attacker may be able to leverage this issue to inject arbitrary 
HTML and script code into a user's browser to be executed within the
security context of the affected site."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Unknown at this time."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/12/15"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/12/23"
  );
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);


# Loop through directories and try to exploit the issue.
if (thorough_tests) dirs = list_uniq(make_list("/daloradius", cgi_dirs()));
else dirs = make_list(cgi_dirs());

alert = string('>">', "<script>alert('", SCRIPT_NAME, "')</script>");
vuln = test_cgi_xss(
  port     : port,
  cgi      : "/login.php",
  dirs     : dirs,
  qs       : "error="+urlencode(str:alert),
  pass_str : alert+'<br/><br/>either of the following',
  pass2_re : "title>daloRADIUS"
);
if (!vuln) exit(0, "No vulnerable installs of daloRADIUS were discovered on the web server on port "+port+".");
