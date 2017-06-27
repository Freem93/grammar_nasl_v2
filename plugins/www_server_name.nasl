#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11239);
 script_version ("$Revision: 1.25 $");

 script_osvdb_id(2110);
 
 script_name(english:"Web Server Crafted Request Vendor/Version Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web server that may be leaking information." );
 script_set_attribute(attribute:"description", value:
"The web server running on the remote host appears to be hiding its version
or name, which is a good thing. However, using a specially crafted request,
Nessus was able to discover the information." );
 script_set_attribute(attribute:"solution", value:
"No generic solution is known. 
Contact your vendor for a fix or a workaround." );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/02/19");
 script_cvs_date("$Date: 2015/12/23 16:43:02 $");
 script_set_attribute(attribute:"plugin_type", value: "remote");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();
 
 script_summary(english:"Tries to discover the web server name");
 script_category(ACT_GATHER_INFO); 
 script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("httpver.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 1, dont_break: 1);

w = http_send_recv3(port: port, method: "GET", item: "/", exit_on_fail: 1);

# If anybody can get the server name, exit
srv = '^Server: *([^ \t\n\r]+)';
if (egrep(string: w[1], pattern: srv, icase: 1))
 exit(0, "The web server on port "+port+" sends a Server header.");

i = 0;
req[i++] = 'HELP\r\n\r\n';
req[i++] = 'HEAD / \r\n\r\n';
req[i++] = 'HEAD / HTTP/1.0\r\n\r\n';
req[i++] = strcat('HEAD / HTTP/1.1\r\nHost: ', get_host_name(), '\r\n\r\n');

for (i = 0; ! isnull(req[i]); i ++)
{
  w = http_send_recv_buf(port: port, data: req[i], exit_on_fail: 0);
  if (! isnull(w))
  {
    v = eregmatch(string: w[1], pattern: srv, icase: 1);
    if (! isnull(v))
    {
     s1 = v[1];
     rep = "
After sending this request :
" + http_last_sent_request() + "
Nessus was able to gather the following information from the web server :
" + s1;
     r = strcat(w[0], w[1]);
     security_note(port:port, extra: rep);
     debug_print("Request: ", chomp(req[i]), " - Server: ", s1);

      # We check before: creating a list is not a good idea
      sb = string("www/banner/", port);
      if (! get_kb_item(sb))
        replace_kb_item(name: sb, value: r);
      else
      {
        sb = string("www/alt-banner/", port);
        if (! get_kb_item(sb))
          replace_kb_item(name: sb, value: r);
      }
      exit(0);
    }
  }
}
