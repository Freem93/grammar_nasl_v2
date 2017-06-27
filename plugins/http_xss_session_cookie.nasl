#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(48432);
 script_version ("$Revision: 1.8 $");
 script_cvs_date("$Date: 2015/01/14 03:46:10 $");
 
 script_name(english: "Web Application Session Cookies Not Marked HttpOnly");
 script_summary(english: "Check the session cookie");

 script_set_attribute(attribute:"synopsis", value:
"HTTP session cookies might be vulnerable to cross-site scripting
attacks." );

 script_set_attribute(attribute:"description", value:
"The remote web application uses cookies to track authenticated users. 
However, one or more of those cookies are not marked 'HttpOnly',
meaning that a malicious client-side script such as JavaScript could
read them. 

'HttpOnly' is a security mechanism to protect against cross-site
scripting attacks that was proposed by Microsoft and initially
implemented in Internet Explorer.  All modern browsers support it. 

Note that :

  - 'HttpOnly' can be circumvented in some cases.

  - The absence of this attribute does not mean that the web
    application is automatically vulnerable to cross-site 
    scripting attacks.

  - Some web applications need to manipulate the session 
    cookie through client-side scripts and the 'HttpOnly' 
    attribute cannot be set." );
  script_set_attribute(attribute:"solution", value:
"If possible, add the 'HttpOnly' attribute to all session cookies.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/25");
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?916b20e4");
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?6752aae7");
 script_set_attribute(attribute:"plugin_type", value: "remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english: "This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencies("http_session_cookie.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

#

port = get_http_port(default: 80, embedded: TRUE);

ck = get_kb_list("SessionCookie/"+port+"/key");
if (isnull(ck)) exit(0, "No session cookies were found on port "+port+".");

n = 0; sec = 0; txt = '';
foreach k (make_list(ck))
{
  n ++;
  if (get_kb_item("/tmp/SessionCookie/"+port+"/"+k+"/httponly"))
    sec ++;
  else
    txt = strcat(txt, get_kb_item("SessionCookie/"+port+"/as_text/"+k), '\n');
}

# It is likely that we have only one session cookie. Anyway, if the 
# web application has an uncommon architecture, http_session_cookie.nasl
# will pick every cookie that is compulsory for session tracking.
# This means that we need all cookies to steal the session. Marking only one
# of them as "HttpOnly" is weak but not completely insecure.

if (n == 0)
  exit(1, "No session cookies were found on port "+port+".");

if (sec > 0)
    exit(0, ""+sec+" out of "+n+" session cookies on port "+port+" are safe.");

rep = '';
if (n == 1)
  rep = '\nThe session cookie is not marked \'HttpOnly\'.\n';
else
  rep = '\nThe session cookies are not marked \'HttpOnly\'.\n';

if (report_verbosity > 1)
{
  if (n == 1) rep += '\nHere is the insecure cookie :\n\n';
  else rep += '\nHere are the insecure cookies :\n\n';
  rep += txt;
}
security_warning(port: port, extra: rep);
