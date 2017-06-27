#
# (C) Tenable Network Security, Inc.
#

# Thanks to Sullo for testing this plugin.


include("compat.inc");

if(description)
{
 script_id(10762);
 script_version ("$Revision: 1.22 $");
 script_cvs_date("$Date: 2011/03/11 21:18:09 $");

 script_name(english: "RTSP Server Type / Version Detection");

 script_set_attribute(attribute:"synopsis", value:
"An RTSP (Real Time Streaming Protocol) server is listening on the
remote port." );
 script_set_attribute(attribute:"description", value:
"The remote server is an RTSP server.  RTSP is a client-server
multimedia presentation protocol, which is used to stream videos and
audio files over an IP network. 

It is usually possible to obtain the list of capabilities and the
server name of the remote RTSP server by sending an OPTIONS request." );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Rtsp" );
 script_set_attribute(attribute:"solution", value:
"Disable this service if you do not use it." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/09/14");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "RTSP Server detection");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 script_family(english: "Service detection");
 script_dependencie("find_service2.nasl");
 script_require_ports("Services/rtsp", 554);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_kb_item("Services/rtsp");
if ( ! port ) port = 554;

if (! get_port_state(port)) exit(0);

 soc = open_sock_tcp(port);
 if ( ! soc ) exit(0);

 send(socket:soc, data:'OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n');
 r = http_recv3(socket:soc);
 if (isnull(r)) exit(0);
 if ( ereg(pattern:"(RTSP/1\.[0-9] 200 OK|.* RTSP/1\.[0-9]$)", string:r[0]) && egrep(pattern:"^C[Ss]eq:", string:r[1]) )
 {
   h = parse_http_headers(status_line: r[0], headers: r[1]);
   serv = h["server"];
   if (! serv ) serv = h["via"];
   
   report = "";
   if (serv) 
   {
     report += string("\nServer Type : ", serv , "\n");
     set_kb_item(name:string("rtsp/server/",port), value:serv);	 
   }
   report += string(
    "\n",
    "The remote RSTP server responds to an 'OPTIONS *' request as follows :\n",
    "\n",
    crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
    r[1], "\n",
    crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
   );

   if (report_verbosity > 0) security_note(port:port, extra:report);
   else security_note(port);
 }
