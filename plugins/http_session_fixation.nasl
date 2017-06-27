#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(45084);
 script_version ("$Revision: 1.15 $");
 script_cvs_date("$Date: 2017/05/16 19:35:39 $");
 

 script_name(english: "Session Fixation Attack on HTTP Cookies");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web application is vulnerable to a session fixation
attack." );
 script_set_attribute(attribute:"description", value:
"By manipulating cookies through a vulnerability similar to cross-site
scripting, an attacker can set the session cookies.  The legitimate
user will be logged out of the application and after he logs in again,
the cookie will remain unchanged and the attacker will be able to
steal the open session and impersonate the user." );
 script_set_attribute(attribute:"solution", value: 
"- Fix the application so that the session cookie is re-generated
   after a successful authentication.

- Fix the cookie manipulation flaws." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cwe_id(
  287, # Improper Authentication
  384, # Session Fixation
  718, # OWASP Top Ten 2007 Category A7 - Broken Authentication and Session Management
  724, # OWASP Top Ten 2004 Category A3 - Broken Authentication and Session Management
  812, # OWASP Top Ten 2010 Category A3 - Broken Authentication and Session Management
  928, # Weaknesses in OWASP Top Ten 2013
  930, #  OWASP Top Ten 2013 Category A2 - Broken Authentication and Session Management
  935  # OWASP Top Ten 2013 Category A7 - Missing Function Level Access Control
 );
 script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Session_fixation");
 script_set_attribute(attribute:"see_also", value:"http://www.owasp.org/index.php/Session_Fixation");
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/03/17");
 script_set_attribute(attribute:"plugin_type", value: "remote");
 script_end_attributes();

 script_summary(english: "Session fixation attack (HTTP cookies)");
 script_category(ACT_ATTACK);
 script_copyright(english: "This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencies("http_login.nasl", "http_session_cookie.nasl", "torture_cgi_header_injection.nasl", "torture_cgi_cookie_manip.nasl", "cookie_manipulation.nasl", "fixed_session_cookies.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default: 80, embedded: TRUE);

if (! get_kb_item("www/"+port+"/fixed_session_cookies"))
  exit(0, "No session cookies are used on port "+port+" or they are regenerated after login.");

if (! get_kb_item(strcat("www/", port, "/generic_xss")) &&
    ! get_kb_item(strcat("www/", port, "/generic_cookie_injection")))
{
  l = get_kb_list("www/"+port+"/cgi_CM/*/*");
  if (isnull(l))
  {
    l = get_kb_list("www/"+port+"/cgi_HI/*/*");
      exit(0, 
"The web application on port "+port+" is not vulnerable to cookie manipulation." );
  }
}

security_hole(port);

