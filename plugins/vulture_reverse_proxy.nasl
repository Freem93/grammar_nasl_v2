#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(39328);
 script_version("$Revision: 1.6 $");

 script_name(english:"Vulture Reverse Proxy Detection");

 script_set_attribute(attribute:"synopsis", value:
"A reverse proxy is running on this proxy." );
 script_set_attribute(attribute:"description", value:
"This web server appears to be protected by a Vulture reverse proxy as
it has a script for Vulture's login page." );
 script_set_attribute(attribute:"see_also", value:"http://vulture.open-source.fr/wiki/" );
 script_set_attribute(attribute:"solution", value:
"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2009/06/08");
 script_cvs_date("$Date: 2011/03/14 21:48:15 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Identify Vulture login page"); 
 script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Web Servers"); 
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 443);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default: 443, embedded: 0);
b = http_get_cache(port: port, item: "/", exit_on_fail: 1);
if ("vulture_app" >!< b) exit(0);

r = http_send_recv3(port: port, method: "GET", item: "/", follow_redirect:1, exit_on_fail: 1);
if (r[0] !~ "^HTTP/1\.1 200 ") exit(0);

l = get_http_cookies_names(port: port, name_regex: "^vulture_[a-z]+");
if (isnull(l) || max_index(l) == 0) exit(0);

refresh = egrep(string: r[2], pattern: '<meta http-equiv="refresh" ', icase: 1);
if (! refresh) exit(0);

l = eregmatch(string: refresh, pattern: 'content="[0-9]+;url=https?://[^/]+(/[^"]+)">', icase:1);
if (isnull(r)) exit(0);

r = http_send_recv3(port: port, method: "GET", item: l[1], exit_on_fail: 1);

 if ( '<body onload="document.auth_form.vulture_login.focus();">' >< r[2] &&
      '<input type=hidden name=Vulture_portail value=>' >< r[2] &&
      '<input type="text" name="vulture_login">' >< r[2] && 
      '<input type="password" autocomplete="off" name="vulture_password">' >< r[2] )
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Vulture's login page can be accessed via the following URL :\n",
      "\n",
      "  ", build_url(port:port, qs:l[1]), "\n"
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
  set_kb_item(name: 'www/'+port+'/vulture', value: TRUE);
}
