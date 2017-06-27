#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(85602);
 script_version ("$Revision: 1.1 $");
 script_cvs_date("$Date: 2015/08/24 19:31:49 $");

 script_name(english: "Web Application Cookies Not Marked Secure");
 script_summary(english: "Find cookies missing the secure flag.");

 script_set_attribute(attribute:"synopsis", value:
"HTTP session cookies might be transmitted in cleartext." );
 script_set_attribute(attribute:"description", value:
"The remote web application sets various cookies throughout a user's
unauthenticated and authenticated session. However, there are
instances where the application is running over unencrypted HTTP or
the cookies are not marked 'secure', meaning the browser could send
them back over an unencrypted link under certain circumstances. As a
result, it may be possible for a remote attacker to intercept these
cookies.

Note that this plugin detects all general cookies missing the 'secure'
cookie flag, whereas plugin 49218 (Web Application Session Cookies
Not Marked Secure) will only detect session cookies from an
authenticated session missing the secure cookie flag.");
 script_set_attribute(attribute:"see_also", value: "https://www.owasp.org/index.php/SecureFlag");
 script_set_attribute(attribute:"solution", value:
"Each cookie should be carefully reviewed to determine if it contains
sensitive data or is relied upon for a security decision.

If possible, ensure all communication occurs over an encrypted channel
and add the 'secure' attribute to all session cookies or any cookies
containing sensitive data.");
 script_cwe_id(
   522, # Insufficiently Protected Credentials
   718, # OWASP Top Ten 2007 Category A7 - Broken Authentication and Session Management
   724, # OWASP Top Ten 2004 Category A3 - Broken Authentication and Session Management
   928, # Weaknesses in OWASP Top Ten (2013)
   930 # OWASP Top Ten 2013 Category A2 - Broken Authentication and Session Management
 );

 script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/24");

 script_set_attribute(attribute:"plugin_type", value: "remote");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english: "Web Servers");

 script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

 script_dependencies("webmirror.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

load_cookiejar();

port = get_http_port(default: 80, embedded: TRUE);
keys_l = get_http_cookie_keys(name_re: ".*", port: port);
report = "";
s_cookies = 0;

if (empty_or_null(keys_l)) exit(1, "CookieJar is empty or returns null.");

foreach k (keys_l)
{
  h = get_http_cookie_from_key(k);
  if (empty_or_null(h)) continue;

  if (h['secure'] == '0')
  {
      str = strcat(
           'Name : ', h['name'],
         '\nPath : ', h['path'],
         '\nValue : ', h['value'],
         '\nDomain : ', h['domain'],
         '\nVersion : ', h['version'],
         '\nExpires : ', h['expires'],
         '\nComment : ', h['comment'],
         '\nSecure : ', h['secure'],
         '\nHttponly : ', h['httponly'],
         '\nPort : ', h['port'], '\n' );

      report = strcat(report, '\n', str, '\n');
      s_cookies+=1;
  }
}


if (strlen(report) > 0)
{
  if (report_verbosity > 0)
  {
    if (s_cookies > 1) s = 's do';
    else s = ' does';

    report = strcat('\nThe following cookie'+s+' not set the secure cookie flag :\n', report);
    security_note(port: port, extra: report);
  }
  else security_note(port);
}
else exit(1, "This web application is not affected.");
