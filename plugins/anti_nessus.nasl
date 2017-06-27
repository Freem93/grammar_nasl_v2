#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11238);
 script_version ("$Revision: 1.26 $");
 script_name(english: "Anti-Nessus Defense Detection");
 script_summary(english: "Detects anti Nessus features");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote web server appears to have filtering enabled."
 );
 script_set_attribute(attribute:"description", value:
"It appears that the remote web server rejects requests from Nessus.
It is possibly protected by a reverse proxy." );
 script_set_attribute(attribute:"solution", value:
"In order to ensure accurate results, change the web server's
configuration to allow access to Nessus." );
 script_set_attribute(
   attribute:"risk_factor", 
   value:"None"
 );
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/02/19");
 script_cvs_date("$Date: 2011/03/14 21:48:01 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO); 
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencie("http_version.nasl", "find_service1.nasl", "httpver.nasl", "no404.nasl");
 script_require_ports("Services/www",  80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ExperimentalScripts");
 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# Still broken?
if (! experimental_scripts)
 exit(0, "This script only runs in 'experimental' mode.");

port = get_http_port(default:80, embedded: 1);

no404 = get_kb_item(string("www/no404/", port));

if (no404)
 rep = "
It seems that the web server is rejecting requests due to a filter.
However, because of the way the filter is implemented, it may
help a script kiddy that uses Nessus to scan your system.";

http_disable_keep_alive();

u = string("/NessusTest", rand(), ".html");
r = http_send_recv3(method: "GET", port: port, item: u, exit_on_fail: TRUE);
v = parse_http_headers(status_line: r[0], headers: r[1]);
x1 = v["$code"];

u = string("/", rand_str(), ".html");
r = http_send_recv3(method: "GET", port: port, item: u, exit_on_fail: TRUE);
v = parse_http_headers(status_line: r[0], headers: r[1]);
x2 = v["$code"];

if (x1 != x2)
{
  if (no404) security_note(port: port, extra: rep);
  else security_note(port);

  set_kb_item(name: string("www/anti-nessus/",port,"/rand-url"), value: TRUE);
  exit(0);
}

# No test on the User-Agent, as Nessus now mimics IE by default

exit(0, "The remote web server on port "+port+" is not affected.");
