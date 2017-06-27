#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10582);
 script_version ("$Revision: 1.36 $");
 
 script_name(english:"HTTP Protocol Version Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"HTTP protocol version." );
 script_set_attribute(attribute:"description", value:
"This script determines which version of the HTTP protocol the remote
host is speaking" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/12/28");
 script_cvs_date("$Date: 2011/03/14 21:48:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "HTTP version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2011 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("apache_SSL_complain.nasl", "doublecheck_std_services.nasl", "http11_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# Do not use get_http_port() here
port = get_kb_item("Services/www");
if (! port) port = 80;
if (! get_port_state(port)) exit(0, "Port "+port+" is closed.");
if (get_kb_item("Services/www/"+port +"/broken"))
 exit(0, "Server on port "+port+" is broken.");

http_disable_keep_alive();

w = http_send_recv3(method:"GET", item:"/", version: 11, port: port);
if (! isnull(w) &&
    ereg(string:w[0], pattern:"^HTTP/.* 30[0-9] ") &&
    egrep(pattern:"^Server: EZproxy", string:w[1]) )
{
   report = 
"The remote port seems to be running EZproxy, a proxy server which
opens many HTTP ports to simply to perform HTTP redirections.

Nessus will not perform HTTP tests again the remote port, since they
would consume time and bandwidth for no reason

See also : 

http://www.usefulutilities.com/support/rewrite.html";
		if (NASL_LEVEL < 3000)
  		  security_note(port:port, data:report);
		else
  		  security_note(port:port, extra:report);
		set_kb_item(name:"Services/www/" + port + "/broken", value:TRUE);
		set_kb_item(name:"Services/www/" + port + "/broken/reason", value:"EZproxy");
		set_kb_item(name: "Services/www/"+port+"/declared_broken_by", value: SCRIPT_NAME);
 		 exit(0);
}

# MA 2009-02-08: we should be strict here, as some web servers 
# (e.g. IBM Cognos Express) return 500 on /
#
# 500 Internal Server Error
# 501 Not Implemented
# 502 Bad Gateway
# 503 Service Unavailable
# 504 Gateway Timeout
# 505 HTTP Version Not Supported

if(! isnull(w) &&
     ereg(string:w[0], pattern:"^HTTP/.* [0-9]*")  &&
   ! ereg(string:w[0], pattern:"^HTTP/.* 50[1-5]") )
{
  	  set_kb_item(name:string("http/", port), value:"11");
	  exit(0);
}
else 
{
  w = http_send_recv3(port: port, method:"GET", item:"/", version: 10);
  if(! isnull(w) && ereg(string:w[0], pattern:"^HTTP/.* [0-9]*") )
  {
    if ( ereg(string:w[0], pattern:"^HTTP/.* 50[1-5]") )
    {
      code = '50x';
      i = stridx(w[0], ' 50');
      if (i >= 0) code = int(substr(w[0], i+1));
      declare_broken_web_server(port: port, reason:
'The web server returns '+code+' when / is requested.');
    }
   	else
 	 set_kb_item(name:string("http/", port), value:"10");
	exit(0);
   }
   else
   {
       w = http_send_recv3(method:"GET", port:port, item: "/", version: 9);
       if (! isnull(w) && ("HTML" >< w[0] || "200" >< w[0]))
         {
           set_kb_item(name:string("http/", port), value:"09");
	   exit(0);
         }
   }
}


# The remote server does not speak http at all. We'll mark it as
# 1.0 anyway
if(port == 80)
{
 set_kb_item(name:string("http/", port), value:"10");
}
