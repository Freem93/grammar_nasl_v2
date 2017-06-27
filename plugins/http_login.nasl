#
# (C) Tenable Network Security, Inc.
#

# @PREFERENCES@

include("compat.inc");

if(description)
{
 script_id(11149);
 script_version ("$Revision: 1.34 $");
 script_cvs_date("$Date: 2014/06/06 13:46:59 $");
 
 script_name(english: "HTTP login page");
 
 script_set_attribute(attribute:"synopsis", value:
"HTTP form based authentication." );
 script_set_attribute(attribute:"description", value:
"This script logs onto a web server through a login page and
stores the authentication / session cookie." );
 script_set_attribute(attribute:"solution", value: "n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/10/26");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Log through HTTP page");
 script_category(ACT_GATHER_INFO);	# Has to run after find_service
 script_copyright(english: "This script is Copyright (C) 2002-2014 Tenable Network Security, Inc.");
 script_family(english: "Settings");

 # We first visit this page to get a cookie, just in case
 script_add_preference(name:"Login page :", type: "entry", value: "/");
 # Then we submit the username & password to the right form
 script_add_preference(name:"Login form :", type: "entry", value: "");
 # Here, we allow some kind of variable substitution. 
 script_add_preference(name:"Login form fields :", type: "entry", 
	value:"user=%USER%&pass=%PASS%");
 script_add_preference(name:"Login form method :", type:"radio", value:"POST;GET");
 script_add_preference(name:"Automated login page search", type:"checkbox", value:"no");
## if (defined_func("mutex_lock"))
   script_add_preference(name: "Re-authenticate delay (seconds) : ", type: "entry", value: "");

 script_add_preference(name:"Check authentication on page : ", type: "entry", value: "");
 script_add_preference(name:"Follow 30x redirections (# of levels) :", type: "entry", value: "2");
 script_add_preference(name:"Authenticated regex : ", type: "entry", value: "");
 script_add_preference(name:"Invert test (disconnected if regex matches)", type: "checkbox", value: "no");
 script_add_preference(name:"Match regex on HTTP headers", type: "checkbox", value: "no");
script_add_preference(name:"Case insensitive regex", type: "checkbox", value: "no");
script_add_preference(name:"Abort web application tests if login fails", type:"checkbox", value:"no");
 script_dependencie("find_service1.nasl", "httpver.nasl", "logins.nasl", "web_app_test_settings.nasl", "broken_web_server.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

# The script code starts here

http_login = get_kb_item("http/login");
http_pass = get_kb_item("http/password");
http_login_form = script_get_preference("Login form :");
http_login_page = script_get_preference("Login page :");
http_login_fields = script_get_preference("Login form fields :");
http_login_meth = script_get_preference("Login form method :");
if (http_login_meth != "POST" && http_login_meth != "GET")
 http_login_meth = "POST";

automatic_http_login = 0;
opt = script_get_preference("Automated login page search");
if ("yes" >< opt && "no" >!< opt)
  set_kb_item(name:"Settings/HTTP/automatic_http_login", value: TRUE);

if (http_login_page)
  set_kb_item(name:"Settings/HTTP/http_login_page", value: http_login_page);
if (http_login_meth)
  set_kb_item(name:"Settings/HTTP/http_login_meth", value: http_login_meth);

if (! http_login_form)
  exit(1, 'The "Login form" scan policy setting has not been filled in.');
if (! http_login_fields)
  exit(1, 'The "Login form fields" scan policy setting has not been filled in.');

set_kb_item(name:"Settings/HTTP/http_login_form", value: http_login_form);
set_kb_item(name:"Settings/HTTP/http_login_fields", value: http_login_fields);

opt = script_get_preference("Abort web application tests if login fails");
if ("yes" >< opt && "no" >!< opt)
{
  abort_if_fail = 1;
  set_kb_item(name:"Settings/HTTP/abort_if_login_fail", value: TRUE);
}
else
  abort_if_fail = 0;

http_login_check_page = script_get_preference("Check authentication on page : ");
if (http_login_check_page)
  set_kb_item(name:"Settings/HTTP/http_login_check_page", value: http_login_check_page);

if (!http_login_check_page)
  exit(1, 'The "Check authentication on page" scan policy setting has not been filled in.');

opt = script_get_preference("Follow 30x redirections (# of levels) :");
http_login_follow_redir = int(opt);
if (http_login_follow_redir < 0) http_login_follow_redir = 0;
set_kb_item(name:"Settings/HTTP/http_login_follow_redir", value: http_login_follow_redir);

http_login_regex = script_get_preference("Authenticated regex : ");
if (http_login_regex)
  set_kb_item(name:"Settings/HTTP/http_login_regex", value: http_login_regex);

if (!http_login_regex)
  exit(1, 'The "Authenticated regex" scan policy setting has not been filled in.');

opt = script_get_preference("Invert test (disconnected if regex matches)");
http_login_regex_invert =  ("no" >!< opt && "yes" >< opt);
set_kb_item(name:"Settings/HTTP/http_login_regex_invert", value: http_login_regex_invert);

opt = script_get_preference("Match regex on HTTP headers");
http_login_regex_headers =  ("no" >!< opt && "yes" >< opt);
set_kb_item(name:"Settings/HTTP/http_login_regex_headers", value: http_login_regex_headers);

opt = script_get_preference("Case insensitive regex");
http_login_regex_icase =  ("no" >!< opt && "yes" >< opt);
set_kb_item(name:"Settings/HTTP/http_login_regex_icase", value: http_login_regex_icase);

http_set_read_timeout(2 * get_read_timeout());	# safer

if (http_login)
{
  http_login_fields = ereg_replace(string: http_login_fields,
	pattern: "%USER%", replace: urlencode(str:http_login));
}
if (http_pass)
{
  http_login_fields = ereg_replace(string: http_login_fields,
	pattern: "%PASS%", replace: urlencode(str:http_pass));
}

port = get_http_port(default:80, embedded: TRUE, dont_break: TRUE);

enable_cookiejar();

e = http_form_login(port: port, page: http_login_page, 
  save_cookies: TRUE, method: http_login_meth,
  form: http_login_form, fields: http_login_fields, 
  check_page: http_login_check_page, regex: http_login_regex,
  re_invert: http_login_regex_invert, re_headers: http_login_regex_invert, 
  follow_redirect: http_login_follow_redir,
  re_icase: http_login_regex_icase);

if (e != "OK" && e != "")	# Failed
{
  if (report_verbosity > 0)
  {
    rep = e;
    extra = 'HTTP login failed :\n' + rep;
    if (report_verbosity > 1)
    {
      extra = 'HTTP login failed using the following request : \n\n' +
      http_last_sent_request() + '\n' + rep;
    }
    security_note(port:port, extra:extra);
  }
  if (abort_if_fail)
    set_kb_item(name:"www/"+port+"/no_web_app_tests", value: TRUE);
  set_kb_item(name:"/tmp/www/"+port+"/automatic_http_login", value: TRUE);
  exit(1, e);
}
else if (report_verbosity > 0 && e == "OK")
{
  extra = 'HTTP login succeeded';
  if (report_verbosity > 1)
    extra += ' with the following request : \n\n' + http_last_sent_request();

  security_note(port:port, extra:extra);
}
else if (report_verbosity > 0 && e == "") # empty string means "maybe"
{
  extra = '\nNessus was unable to determine if the login succeeded';
  if (report_verbosity > 1)
    extra += ' using the following request : \n\n' + http_last_sent_request();

  security_note(port: port, extra:extra);
}  

# Compatibility with old code
rq = http_mk_get_req(item: "/", port: port);
cookies = rq["Cookie"];
if (cookies)
  set_kb_item(name: string("/tmp/http/auth/", port), value: 'Cookie: '+cookies);
else
{
  debug_print("No cookie is set. Old authentication will fail.\n");
  # exit(1, "No cookie is set. Authentication failed");
}

#

if (http_login_page)
  set_kb_item(name: "www/"+port+"/login_page", value: http_login_page);
if (http_login_form)
  set_kb_item(name: "www/"+port+"/login_form", value: http_login_form);
if (http_login_fields)
  set_kb_item(name: "www/"+port+"/login_fields", value: http_login_fields);
if (http_login_meth)
  set_kb_item(name: "www/"+port+"/login_meth", value: http_login_meth);

set_kb_item(name: "www/"+port+"/login_follow_30x", value: http_login_follow_redir);

if (http_login_check_page)
  set_kb_item(name: "www/"+port+"/check_page", value: http_login_check_page);
if (http_login_regex)
  set_kb_item(name: "www/"+port+"/check_regex", value: http_login_regex);
if (http_login_regex_invert)
  set_kb_item(name: "www/"+port+"/regex_invert", value: http_login_regex_invert);
if (http_login_regex_headers)
  set_kb_item(name: "www/"+port+"/regex_headers", value: http_login_regex_headers);
if (http_login_regex_icase)
  set_kb_item(name: "www/"+port+"/regex_icase", value: http_login_regex_icase);

##if (defined_func("mutex_lock"))
{
  delay = script_get_preference("Re-authenticate delay (seconds) : ");
  if (delay == "") delay = 0;
  else             delay = int(delay);
  if (delay > 0) set_kb_item(name: "www/"+port+"/login_delay", value: delay);
}

replace_kb_item(name: "www/"+port+"/login_time", value: unixtime());
