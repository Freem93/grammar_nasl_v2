#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(46201);
 script_version("$Revision: 1.9 $");
 script_cvs_date("$Date: 2017/05/18 17:50:12 $");

 script_name(english:"Fixed HTTP Session Cookies");
 script_summary(english:"Fix a session cookie & log again.");

 script_set_attribute(attribute:"synopsis", value:
"The remote web application is affected by a session fixation
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote web application uses cookies to track authenticated users.
If the session cookie is already present before authentication, it
remains unchanged after a successful login. A remote attacker can
exploit this to hijack a valid user session.

Session cookies are expected to be unpredictable in a secure web
application. If HTTP cookies can be manipulated (by injecting client-
side JavaScript for example) then the attacker does not have to break
the pseudo-random generator, and the web application is vulnerable to
a 'session fixation' attack.");
 script_set_attribute(attribute:"solution", value:
"Fix the application so that the session cookie is re-generated after
successful authentication.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Session_fixation");
 script_set_attribute(attribute:"see_also", value:"http://www.owasp.org/index.php/Session_Fixation");
 script_set_attribute(attribute:"see_also", value:"http://phpsecurity.org/ch04.pdf");

 script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/30");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencies("http_login.nasl", "http_session_cookie.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default: 80, embedded: TRUE);

cookies_l = get_kb_list("SessionCookie/"+port+"/key");
if (isnull(cookies_l))
  exit(0, "No session cookies were identified on port "+port+".");

init_cookiejar();

my_val = make_array();
foreach ck (cookies_l)
{
  h = get_http_cookie_from_key(ck);
  if (isnull(h)) continue;
  v = rand();
  h["value"] = v;
  my_val[ck] = v;
  set_http_cookie_from_hash(h);
}

http_reauthenticate_if_needed(port: port);
# Verify that we were able to authenticate first
if (get_kb_item("www/"+port+"/"+SCRIPT_NAME+"/auth_KO"))
  exit(0, "Web authentication failed on port ", port, " for ", SCRIPT_NAME);

txt = '';
mod = 0; all = 0;
foreach ck (cookies_l)
{
  h = get_http_cookie_from_key(ck);
  if (isnull(h)) continue;
  all ++;
  if (h["value"] != my_val[ck])
    mod ++;
  else
    txt = strcat(txt, h["name"], ' = ', h["value"], '\n');
}

if (all == 0)
  exit(1, "No session cookie was set on port "+port+".");

if (mod > 0)
  if (report_paranoia < 2)
    exit(0, "A session cookie on port "+port+" was modified.");
  else if (mod == all)
    exit(0, "All session cookies on port "+port+" were modified.");

report = NULL;
if (report_verbosity > 0)
  report = '\nThe following cookies were not changed after login :\n\n'+txt;

security_warning(port:port, extra: report);
set_kb_item(name: "www/"+port+"/fixed_session_cookies", value: TRUE);
