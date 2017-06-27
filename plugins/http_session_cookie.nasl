#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(44987);
 script_version ("$Revision: 1.7 $");
 script_cvs_date("$Date: 2015/08/24 19:31:49 $");
 
 script_name(english: "HTTP Session Cookies");
 script_summary(english: "Find the session cookie.");
 
 script_set_attribute(attribute:"synopsis", value:
"HTTP session cookies used on the remote web server can be identified." );
 script_set_attribute(attribute:"description", value:
"The remote web application uses cookies to track authenticated users. 
By removing the cookies, one-by-one, and checking a protected page, it
is possible to identify these cookies.");
 script_set_attribute(attribute:"solution", value: "n/a" );

 script_set_attribute(attribute:"plugin_publication_date",value:"2010/03/04");

 script_set_attribute(attribute:"plugin_type", value: "remote");
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english: "Web Servers");

 script_copyright(english: "This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

 script_dependencies("http_login.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default: 80, embedded: TRUE);
s_cookies = 0;

cp = get_kb_item("www/"+port+"/check_page");
re = get_kb_item("www/"+port+"/check_regex");
iv = get_kb_item("www/"+port+"/regex_invert");
hd = get_kb_item("www/"+port+"/regex_headers");
ic = get_kb_item("www/"+port+"/regex_icase");
fr = get_kb_item("www/"+port+"/login_follow_30x");

e1 = http_check_authentication(port: port, check_page: cp, regex: re, 
   re_invert: iv, re_headers: hd, re_icase: ic, follow_redirect: fr);

if (e1 == "")
{
  if (report_paranoia < 2)
    exit(0, "HTTP authentication cannot be checked on port "+port+".");
}
else if (e1 != "OK")
  exit(0, "HTTP authentication failed on port "+port+".");

keys_l = get_http_cookie_keys(name_re: ".*", port: port);
if (empty_or_null(keys_l)) exit(1, "CookieJar is empty or returns null.");
report = "";

foreach k (keys_l)
{
  load_cookiejar(jar:"FormAuth");
  h = get_http_cookie_from_key(k);
  if (empty_or_null(h)) continue;
  erase_cookie(k);

  e2 = http_check_authentication(port: port, check_page: cp, regex: re, 
     re_invert: iv, re_headers: hd, re_icase: ic, follow_redirect: fr);
  if (e2 == "OK" || e2 == "") continue;

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
  set_kb_item(name: "SessionCookie/"+port+"/key", value: k);
  set_kb_item(name: "SessionCookie/"+port+"/as_text/"+k, value: str);
  foreach n (keys(h))
    if (! isnull(h[n]))
      set_kb_item(name: "/tmp/SessionCookie/"+port+"/"+k+"/"+n, value: h[n]);
  s_cookies+=1;
}

if (strlen(report) > 0)
{
  if (report_verbosity > 0)
  {
    if (s_cookies > 1) s = 's are';
    else s = ' is';

    report = strcat('\nThe following cookie'+s+' used to track authenticated users :\n', report);
    security_note(port: port, extra: report);
    if (COMMAND_LINE) display(report);
  }
  else security_note(port);
}
else exit(1, "This web application is not affected or session cookies were unable to be determined (i.e. possible authentication issue).");
