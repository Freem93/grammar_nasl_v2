#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(49218);
 script_version ("$Revision: 1.10 $");
 script_cvs_date("$Date: 2016/11/18 21:06:04 $");
 
 
 script_name(english: "Web Application Session Cookies Not Marked Secure");
 script_summary(english: "Check the session cookie");

 script_set_attribute(attribute:"synopsis", value:
"HTTP session cookies may be transmitted in cleartext." );

 script_set_attribute(attribute:"description", value:
"The remote web application uses cookies to track authenticated users. 
However, there are instances where the application is running over 
unencrypted HTTP or the cookie(s) are not marked 'secure', meaning 
the browser could send them back over an unencrypted link under 
certain circumstances. 

As a result, it may be possible for a remote attacker to intercept
these cookies." );
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?916b20e4");
 script_set_attribute(attribute:"solution", value:
"- Host the web application on a server that only provides SSL (HTTPS).

- Mark all cookies as 'secure'." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_cwe_id(
   522,	# Insufficiently Protected Credentials
   718,	# OWASP Top Ten 2007 Category A7 - Broken Authentication and Session Management	
   724,	# OWASP Top Ten 2004 Category A3 - Broken Authentication and Session Management
   928, # Weaknesses in OWASP Top Ten 2013
   930 # OWASP Top Ten 2013 Category A2 - Broken Authentication and Session Management
 );
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/14");
 script_set_attribute(attribute:"plugin_type", value: "remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencies("http_session_cookie.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

#

ports = get_kb_list("Services/www");
if (isnull(ports)) exit(0, "No web service was identified.");
n = 0; sec = 0;
foreach p (make_list(ports))
  if (get_port_state(p) && ! http_is_broken(port: p))
  {
    n ++;
    if (get_port_transport(p) > ENCAPS_IP) sec ++;
  }

if (n == 0) exit(0, "No working web server was found.");
if (sec == n)
  exit(0, "All web services are running over SSL.");

#

port = get_http_port(default: 80, embedded: TRUE);

ck = get_kb_list("SessionCookie/"+port+"/key");
if (isnull(ck)) exit(0, "No session cookie was found on port "+port+".");

ssl = get_port_transport(port);

if (ssl == ENCAPS_IP)
{
  security_warning(port: port, extra: '\nThe web application is available via 
insecure HTTP.');
  exit(0);
}

#

n = 0; sec = 0; txt = '';
foreach k (make_list(ck))
{
  n ++;
  if (get_kb_item("/tmp/SessionCookie/"+port+"/"+k+"/secure"))
    sec ++;
  else
    txt = strcat(txt, get_kb_item("SessionCookie/"+port+"/as_text/"+k), '\n');
}

# It is likely that we have only one session cookie. Anyway, if the 
# web application has an uncommon architecture, http_session_cookie.nasl
# will pick every cookie that is compulsory for session tracking.
# This means that we need all cookies to steal the session. Marking only one
# of them as "secure" is weak but not completely insecure.

if (n == 0)
  exit(1, "No session cookie was found on port "+port+".");

if (sec > 0)
    exit(0, ""+sec+"/"+n+" session cookies on port "+port+" are secure.");

if (n == 1)
  rep = '\nThe session cookie is not marked \'secure\'.\n';
else
  rep = '\nThe session cookies are not marked \'secure\'.\n';

if (report_verbosity > 1)
{
  if (n == 1) rep += '\nHere is the insecure cookie :\n\n';
  else rep += '\nHere are the insecure cookies :\n\n';
  rep += txt;
}

security_warning(port: port, extra: rep);
