#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(31657);
 script_version ("$Revision: 1.10 $");
 script_cvs_date("$Date: 2014/04/25 18:29:33 $");

 script_name(english: "Web Server Uses Non Random Session IDs");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server generates predictable session IDs." );
 script_set_attribute(attribute:"description", value:
"The remote web server generates a session ID for each connection.  A
session ID is typically used to keep track of the actions of a user
while he visits a website. 

The remote server generates non-random session IDs.  An attacker might
use this flaw to guess the session IDs of other users and therefore
steal their session." );
 script_set_attribute(attribute:"see_also", value:"http://pdos.csail.mit.edu/cookies/seq_sessionid.html" );
 script_set_attribute(attribute:"solution", value:
"Configure the remote site and CGIs so as to use random session
IDs." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/03/26");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();


 script_summary(english: "Determines if the remote site sets a random session ID");
 script_category(ACT_GATHER_INFO); 
 
 script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www",80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

global_var NUM_REQUESTS;

NUM_REQUESTS = 5;

function diff(a, b)
{
 local_var i;
 local_var n;
 local_var ret;

 n = strlen(a);
 if ( n > strlen(b) ) n = strlen(b);
 for ( i = 0 ; i < n ; i ++ )
 {
   if ( a[i] != b[i] ) ret++;
 }

 if ( strlen(a) < strlen(b) )
	ret += 5*(strlen(b) - strlen(a));
 else if ( strlen(a) > strlen(b) )
	ret += 5*(strlen(a) - strlen(b));
 return ret;
}

function is_linear(cookies)
{
 local_var i;
 local_var n, m;
 local_var flag;
 
 cookies = sort(cookies);
 if ( max_index(cookies) < 2 ) return 0;
 flag = 0;
 for ( i = 1 ; i < max_index(cookies) ; i ++ )
 {
  if ( cookies[i-1] != cookies[i] ) flag ++; 
  if ( diff(a:cookies[i-1], b:cookies[i]) > 2 ) return 0; 
 }

 if ( flag == 0 ) return 0; # Not a single difference, is this even a session ID ?
 return 1;
}

port = get_http_port(default:80);
if ( ! port ) exit(0);

loc = "/";
r = http_send_recv3(method: "GET", item:loc, port:port);
if ( r[0] =~ "^HTTP/[0-9.]+ 302 " )
{
 v = parse_http_headers(status_line: r[0], headers: r[1]);
 loc = v["location"];
 if ( isnull(loc) ) exit(0);
 if ( tolower(loc) =~ "^http" )
   loc = ereg_replace(pattern:"^https?://[^/]*(/.*)$", replace:"\1", string:loc, icase:TRUE);
}

if ( loc[0] != "/" ) loc = "/" + loc;

trp = get_port_transport(port);
for ( i = 0 ; i < NUM_REQUESTS ; i ++ )
{
 clear_cookiejar();
 r = http_send_recv3(method: "GET", item:loc, port:port);
 if ( r[0] !~ "^HTTP/[0-9.]+ 200 " ) exit(0);
 sec = (trp > ENCAPS_IP);
 v = get_http_cookies_names(name_regex: '^.*ID$', secure: sec);
 if (isnull(v) || max_index(v) <= 0) exit(0);
 cookie[i] = get_http_cookie(name: v[0]);
 name[i] = v[0];
}

if ( is_linear(cookies:cookie) ) 
{
 report = 'Sending several requests gives us the following session IDs :\n\n';
 for (i = 0; i < NUM_REQUESTS ; i ++ )
	report += name[i] + '=' + cookie[i] + '\n';
 security_warning(port:port, extra:report);
}

