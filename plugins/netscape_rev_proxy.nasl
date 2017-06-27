#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(12225);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_name(english:"Web Server Reverse Proxy Detection");
  script_summary(english:"Web Server reverse proxy bug");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to an access control breach.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The remote web server seems to allow any anonymous user
to use it as a reverse proxy.  This may expose internal
services to potential mapping and, henceforth, compromise."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Disable or restrict access the reverse proxy."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
   # http://web.archive.org/web/20100112100209/http://www.sans.org/reading_room/whitepapers/webservers/a_reverse_proxy_is_a_proxy_by_any_other_name_302?show=302.php&cat=webservers
  script_set_attribute(
    attribute:'see_also',
    value:'http://www.nessus.org/u?c4bcdda8'
  );


 script_set_attribute(attribute:"plugin_publication_date", value: "2004/05/04");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");
  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);

w = http_send_recv3(method:"GET", item:"/images", port:port);
if (isnull(w)) exit(1, "The web server on port "+port+" did not answer.");
res = strcat(w[0], w[1]);


# Step[0]
# OK, so there are some reqs before we go any further
# namely, 0) The webserver needs to respond ;-)
# 1) we need a 302 redirect and
# 2) the redirect needs to be to an IP addr and
# 3) the redirect needs to be to an IP other than this webserver

if ("302" >!< w[0]) exit(0, "No 302 redirection on port "+port);
myloc = strstr(res, string("Location: http://") ) ;
myloc2 = strstr(res, string("/images"));
url = strstr(myloc - myloc2, "http");
if ( get_host_name() >< url ) exit(0, "Host name found in new URL on port "+port);
if ( get_host_ip() >< url ) exit(0, "Host IP found in new URL on port "+port);

if (! egrep(string:url, pattern:"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+") )
 exit(0, "No IP address found in new URL on port "+port);



# Step[1]
# initial flagging for IP found
url = ereg_replace(pattern:"http://", replace:"", string:url);
mymsg = string("The remote server seems to divulge information regarding an internal
or trusted IP range.  Specifically, the Location field within the return header
points to the following network: ", url, "\n");

security_warning(port:port, extra:mymsg);


# Step[2]
# onward and upward
# one last fp check...let's make sure the server doesn't just respond
# with 200 OK + default page for any bogus request

w = http_send_recv3(method:"GET", port:port, item:"http://0.0.0.0:31445/");
# Should we exit if w=NULL?
if ("200 OK" >< w[0])
 exit(0, "The web server on port "+port+ "answers 200 to bogus requests.");


# Step[3] ... *finally* let's test the server for proxying capabilities
# so, we'll roll through the /24 denoted in host location, requesting
# http://<IP addr>:139/ ... the reverse proxy should map out the internal
# hosts running netbios ... we can do all this on one HTTP session (hopefully)

octets = split(get_host_ip(), sep:".", keep:0);

for (i=1; i<256; i++)
{
  ip = strcat(octets[0], ".", octets[1], ".", octets[2], ".", i);
  rq = http_mk_proxy_request(scheme: "http", port: 139, host: ip, item: "/", method:"GET", version: 10);
  w = http_send_recv_req(port: port, req: rq);
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer.");
  if ("200 OK" >< w[0] )
  {
        security_warning(port);
        exit(0);
    }
}



