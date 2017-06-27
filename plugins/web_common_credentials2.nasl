#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(52003);
 script_version("$Revision: 1.8 $");
 script_cvs_date("$Date: 2015/12/23 21:38:31 $");

 script_name(english: "Web Common Credentials (HTML form)");
 script_summary(english: "Tests for common web credentials");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to log on with common credentials." );
 script_set_attribute(attribute:"description", value:
"Nessus was able to log on a HTML form using common login / password
combinations." );
 script_set_attribute(attribute:"solution", value:
"Reconfigure the affected server to use a stronger password." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/16");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright("This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");

 script_dependencies("http_version.nasl", "http_login.nasl", "webmirror.nasl");
 script_exclude_keys("global_settings/supplied_logins_only");
 script_timeout(0);
 script_require_ports("Services/www", 80);
 exit(0);
}

# The script code starts here
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi_func.inc");
include("web_common_credentials.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

t = int(get_kb_item("Settings/HTTP/max_run_time"));
if (t <= 0)
  exit(0, "Web app tests are disabled.");
abort_time = unixtime() + t;
  

##

http_login = get_kb_item("http/login");
http_pass = get_kb_item("http/password");

port = get_http_port(default: 80, embedded: 1);

cp = get_kb_item("www/"+port+"/check_page");
if (! cp)
  cp = get_kb_item_or_exit("Settings/HTTP/http_login_check_page");

page = get_kb_item("www/"+port+"/login_page");
if (! page)
  page = get_kb_item("Settings/HTTP/http_login_page");

form = get_kb_item("www/"+port+"/login_form");
if (! form)
  form = get_kb_item_or_exit("Settings/HTTP/http_login_form");

fields = get_kb_item("Settings/HTTP/http_login_fields");
if (! fields)
  fields = get_kb_item_or_exit("www/"+port+"/login_fields");

# Revert to the original string (if possible)
if ("%USER%" >!< fields)
{
  if (http_login == '' || http_login >!< fields)
    exit(1, "Cannot find HTTP username in 'Login form fields' on port="+port+".");
  found = 0;
  foreach f (make_list("login", "username", "user", "id"))
  {
    z = f+'='+http_login;
    if (z >< fields)
    {
      fields = str_replace(find:z, replace: f+"=%USER%", string: fields);
      found = 1;
      break;
    }
  }
  if (! found)
    fields = str_replace(find: http_login, replace: "%USER%", string: fields, count: 1);
}
if ("%PASS%" >!< fields)
{
  if (http_pass == '' || http_pass >!< fields)
    exit(1, "Cannot find HTTP password in 'Login form fields' on port="+port+".");
  found = 0;
  foreach f (make_list("password", "passwd", "pass"))
  {
    z = f+'='+http_pass;
    if (z >< fields)
    {
      fields = str_replace(find:z, replace: f+"=%PASS%", string: fields);
      found = 1;
      break;
    }
  }
  if (! found)
    fields = str_replace(find: http_pass, replace: "%PASS%", string: fields, count: 1);
}

mt = get_kb_item("Settings/HTTP/http_login_meth");
if (! mt)
  mt = get_kb_item("www/"+port+"/login_meth");

re = get_kb_item("www/"+port+"/check_regex");
if (isnull(re))
  re = get_kb_item("Settings/HTTP/http_login_regex");

iv = get_kb_item("www/"+port+"/regex_invert");
if (isnull(iv))
  iv = get_kb_item("Settings/HTTP/http_login_regex_invert");

hd = get_kb_item("www/"+port+"/regex_headers");
if (isnull(hd))
  hd = get_kb_item("Settings/HTTP/http_login_regex_headers");

ic = get_kb_item("www/"+port+"/regex_icase");
if (isnull(ic))
  ic = get_kb_item("Settings/HTTP/http_login_regex_icase");

fr = get_kb_item("www/"+port+"/login_follow_30x");
if (isnull(fr))
  fr = get_kb_item("Settings/HTTP/http_login_follow_redir");

####

clear_cookiejar();
e = http_check_authentication(port: port, check_page: cp, regex: re, re_invert: iv, re_headers: hd, re_icase: ic, follow_redirect: fr);
if (e == "OK" || e == "")
{
 exit(1, "Protected page " + build_url(port:port, qs:cp) + " is always reachable");
}

set_kb_item(name: "/tmp/CouldRun/52003", value: TRUE);

n_err = 0; timeout = 0;

authURL = make_array();
auth_l = mk_list(nc: nc, prevl: authURL);
found = 0;


report = ''; 

for (i = 0; i < nc; i ++)
{
  if (unixtime() >= abort_time)
  {
    timeout ++; 
    break;
  }
  clear_cookiejar();
  f = fields;
  f = str_replace(string: f, find:"%USER%", replace: user[i]);
  f = str_replace(string: f, find:"%PASS%", replace: pass[i]);
  e = http_form_login(port: port, page: page, form: form, fields: f,
        save_cookies: 0, method: mt, 
        check_page: cp, regex: re, re_invert: iv, re_headers: hd, re_icase: ic);
  if (e == "OK")
  {
    authURL[u] = i;
    if (mt == "GET")
      report = strcat(report, build_url(port: port, qs: form+'?'+f), '\n');
    else
      report = strcat(report, build_url(port: port, qs: form), ' [', f, ']\n');
    found ++;
    if (! thorough_tests) break;
  }
}

if (! found)
{
  if (n_err > 3)
    exit(1, "Too many errors encountered while testing the web server on port "+port+".");
  else if (timeout)
    exit(1, "Timeout encountered while testing the web server on port "+port+".");
  else
    exit(0, "No web credentials were found on the web server on port "+port+".");
}

security_hole(port: port, extra: 
'\nCredentials were guessed for these resources :\n\n' + report);
